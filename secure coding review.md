# Secure Code Review: Python User Authentication

## Executive Summary

This review examines a deliberately vulnerable authentication example and its remediated counterpart. The vulnerable example contains two high-risk flaws: SQL injection caused by interpolating login input into SQL with an f-string, and database credentials embedded in source code. In a real deployment, SQL injection could enable authentication bypass or unauthorized access to data, while exposed credentials could grant attackers direct database access. The practical impact depends on database permissions, network exposure, and whether the source or its history has been exposed.

The corrected example uses a parameterized PostgreSQL query, reads connection secrets from environment variables, and verifies a salted PBKDF2 password hash rather than querying for a plaintext password. The example files are [vulnerable_app.py](vulnerable_app.py) and [secure_app.py](secure_app.py).

> **Training warning:** `vulnerable_app.py` is intentionally unsafe and uses a fake placeholder credential. Do not deploy it, connect it to production, or use real credentials with it.

## Scope and Assumptions

- The demonstration targets PostgreSQL using Psycopg 3; install the `psycopg[binary]` package to run either example.
- The vulnerable example assumes a `users` table with `id`, `username`, and plaintext `password` columns solely to make the flawed query understandable. Real systems should not store plaintext passwords.
- The secure example expects `users` to contain `username`, `password_salt` (`BYTEA`), and `password_hash` (`BYTEA`). The registration/provisioning flow that safely creates and stores these hashes is outside this focused review.
- Severity is qualitative. A formal CVSS score cannot be assigned without deployment and threat-model details.

## Vulnerable Example

The complete example is also available in [vulnerable_app.py](vulnerable_app.py).

```python
import getpass
import psycopg

# CRITICAL FLAW: credentials embedded in source code.
DB_HOST = "localhost"
DB_NAME = "training_db"
DB_USER = "training_admin"
DB_PASSWORD = "DEMO_ONLY_replace_this_password"


def authenticate(username, password):
    connection = psycopg.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )

    try:
        with connection.cursor() as cursor:
            # CRITICAL FLAW: user input is interpolated into executable SQL.
            query = (
                f"SELECT id FROM users "
                f"WHERE username = '{username}' AND password = '{password}'"
            )
            cursor.execute(query)
            return cursor.fetchone() is not None
    finally:
        connection.close()


if __name__ == "__main__":
    login_name = input("Username: ")
    login_password = getpass.getpass("Password: ")
    if authenticate(login_name, login_password):
        print("Authentication succeeded.")
    else:
        print("Authentication failed.")
```

## Vulnerability Analysis

| Finding | OWASP Top 10 (2021) | CWE | Severity | Risk and impact |
|---|---|---|---|---|
| SQL injection: `username` and `password` are inserted into SQL text with f-strings. | [A03: Injection](https://owasp.org/Top10/A03_2021-Injection/) | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | **High**; potentially **Critical** if the database account is highly privileged or reachable in a sensitive environment. | Input can alter the meaning of the authentication query. Depending on the database, privileges, and query context, an attacker may bypass authentication, read or modify data, or perform other unauthorized database operations. It also makes query behavior depend on untrusted input. |
| Hardcoded database credentials: connection secrets are constants in the source file. | [A07: Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) (credential management); also relevant to [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | **High** when the source or repository is accessible beyond its intended operators; impact may be **Critical** for a powerful production account. | Anyone who obtains the source, a repository clone, build artifact, or source-control history can recover the credential. Reusing or over-privileging that credential can enable direct database access. Deleting a secret from the latest revision does not remove it from repository history or other copies. |

### Finding 1: SQL Injection

`cursor.execute(query)` receives a completed SQL string whose syntax includes untrusted login input. The database therefore parses user data as part of the SQL command instead of treating it strictly as values. This is especially serious in authentication logic, where a manipulated condition may change the result used to grant access.

**Required fix:** Use the driver's parameter binding (`%s` placeholders with Psycopg) and pass values separately. Do not quote or format placeholders manually.

### Finding 2: Hardcoded Credentials

The database password is stored directly in a tracked source file. Source code and its history are commonly copied to developer machines, code-hosting services, logs, and build artifacts, so a committed secret should be treated as exposed even if later removed.

**Required fix:** Read deployment-specific secrets from a controlled secret source. This example uses environment variables via `os.getenv`/`os.environ`; production deployments should prefer an approved secrets manager where available. Rotate any credential that has already been committed, and grant the application database account only the permissions it needs.

### Additional Authentication Concern

The vulnerable example compares a password against a database column, implying plaintext password storage. That is not a safe storage design. The remediated example instead retrieves a per-user salt and password hash, derives a candidate hash with PBKDF2-HMAC-SHA-256, and compares hashes with `hmac.compare_digest`. For production applications, use a well-maintained password-hashing library and follow current organizational guidance (commonly Argon2id or bcrypt), with appropriate per-user salts and work factors.

## Remediated Example

The complete runnable example is in [secure_app.py](secure_app.py). It requires Psycopg 3 and the environment variables `DB_HOST`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`; `DB_PORT` is optional and defaults to `5432`.

```python
import getpass
import hashlib
import hmac
import os

import psycopg

PBKDF2_ITERATIONS = 600_000


def get_database_config():
    required_names = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
    missing_names = [name for name in required_names if not os.getenv(name)]
    if missing_names:
        raise RuntimeError(
            "Missing required environment variables: " + ", ".join(missing_names)
        )

    return {
        "host": os.environ["DB_HOST"],
        "dbname": os.environ["DB_NAME"],
        "user": os.environ["DB_USER"],
        "password": os.environ["DB_PASSWORD"],
        "port": int(os.getenv("DB_PORT", "5432")),
    }


def authenticate(username, password):
    database_config = get_database_config()

    # SQL command and user-supplied value are passed separately.
    with psycopg.connect(**database_config) as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT password_salt, password_hash "
            "FROM users WHERE username = %s",
            (username,),
        )
        user_record = cursor.fetchone()

    if user_record is None:
        return False

    password_salt, stored_password_hash = user_record
    candidate_password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        password_salt,
        PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(candidate_password_hash, stored_password_hash)


if __name__ == "__main__":
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    try:
        is_authenticated = authenticate(username, password)
    except (RuntimeError, ValueError) as error:
        raise SystemExit("Configuration error: " + str(error)) from error

    if is_authenticated:
        print("Authentication succeeded.")
    else:
        print("Authentication failed.")
```

## Remediation Summary

- **SQL injection:** Replaced SQL string interpolation with a bound parameter (`WHERE username = %s`, `(username,)`). User input is supplied as data, not SQL syntax.
- **Hardcoded secrets:** Removed credentials from source code and load them from environment configuration. Do not commit populated secret files; restrict access to the runtime environment.
- **Password verification:** Query by username, retrieve the stored per-user salt/hash, derive the supplied password's hash, and use a constant-time comparison. Never store or compare plaintext passwords.
- **Operational response:** If real credentials have ever been committed, rotate them immediately, review access logs, and assess repository clones and artifacts. Removing the text from the current file is not sufficient.
- **Least privilege:** Use a dedicated database identity with only the minimum permissions required by the application.

## Running the Example

1. Install Psycopg 3: `python -m pip install "psycopg[binary]"`.
2. Set `DB_HOST`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD` in the local process environment; optionally set `DB_PORT`.
3. Create/populate the secure example's `users` table with username, salt, and password hashes using a separate, secure account-provisioning flow.
4. Run `secure_app.py` from VS Code. Do not run `vulnerable_app.py` against any real or reachable database.

# CS 499 Computer Science Capstone (2024)

**Academic archive | Southern New Hampshire University | April 2024**

This repository preserves my undergraduate computer science capstone and supporting coursework. It illustrates how an authentication prototype evolved from a Java/file-based design to a Python implementation using bcrypt password hashing and an SQLite database.

> **Scope:** This is historical student work, not a deployed application, a maintained authentication library, or a production security reference. The original submissions and milestones are retained to show the progression of the project.

## Project progression

1. **Starting point:** `AuthenticationSystem.java` authenticates against a credentials file and uses MD5 password hashes. This is retained as the **insecure original**, not a recommended approach.
2. **Intermediate iterations:** `Milestone2.py`, `Milestone3 (1).py`, and `Milestone4.py` show the transition to Python, bcrypt, account-management features, and eventually SQLite.
3. **Final submission:** `CS499 Final.py` includes database-backed account records, bcrypt password hashing, unique username generation, temporary-password handling, password-history checks for user-chosen passwords, and an administrative password-reset method.

These files reflect the state of the project at submission. The repository also contains CS 499 journals and written narratives about the development process.

## What the exercise demonstrates

- Recognizing the weaknesses of MD5 and moving to a password-specific hashing algorithm.
- Replacing flat-file credential storage with a relational database.
- Iterative design across authentication, data handling, and account workflows.
- Documenting engineering decisions and security tradeoffs.

## Reviewing the work

The relevant source files are readable directly on GitHub:

- [Original Java prototype](AuthenticationSystem.java)
- [Final Python capstone](CS499%20Final.py)
- [Development milestones](Milestone2.py)
- [Video review of the original Java project](https://youtu.be/CuP-uzfcSKE)

The final Python file defines an `AuthenticationSystem` class; it does **not** include a ready-to-run command-line application or automated tests. It requires Python 3 and the third-party `bcrypt` package. The other imported modules, including `sqlite3`, are from the Python standard library. See [requirements.txt](requirements.txt).

Running the code can create a local `users.db` SQLite file. Do not use real passwords or personal data when evaluating it.

## Important security limitations

This code has **not** been independently security-audited or hardened for production. Known limitations in the preserved academic implementation include:

- Temporary passwords are generated with Python's `random` module instead of the cryptographically secure `secrets` module.
- An authentication-attempt limit is declared but not actually enforced in the final implementation.
- The administrative reset method does not enforce administrator authorization.
- The administrative reset's password-history comparison compares salted bcrypt hash strings directly, which is not an effective password-reuse check.
- Temporary passwords are displayed in console output.
- Automated tests, deployment guidance, and operational controls are absent.

The earlier milestones contain additional incomplete or illustrative behaviors; they should not be reused as authentication components.

**Do not deploy this code as an authentication service.** Its value is as an example of an iterative undergraduate software-security exercise.

## Repository status

Archived coursework, retained for reference. Updates to this README or repository hygiene files do not imply that the 2024 source code has been audited or modernized.

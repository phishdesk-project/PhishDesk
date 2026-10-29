# Record fixtures

All records in this folder are **invented examples** for schema tests.
They are not real dataset entries and do not describe real emails.

- No real email addresses, domains, tokens or credentials.
- Any domain uses a reserved test name (`example.com`, `example.org`, `example.net`, `*.test`, `*.example`).
- `raw_path` files do not exist; tests never read them.
- `tests/test_fixture_hygiene.py` checks these rules in CI.

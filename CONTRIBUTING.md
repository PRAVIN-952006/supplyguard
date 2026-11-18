# Contributing

Create a focused issue or pull request. Changes should include tests for new rules or parser behavior, preserve offline operation, and avoid adding dependencies without a clear justification.

Run:

```bash
python -m unittest discover -s tests
ruff check .
mypy src
```

Do not include real private SBOMs, credentials, customer data, or generated build artifacts in a contribution.

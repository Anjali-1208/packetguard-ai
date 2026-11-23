# Contributing

## Workflow

1. Pull the latest changes: `git pull --rebase origin main`
2. Make one focused change.
3. Check what changed: `git status` and `git diff --stat`
4. Stage only the relevant files: `git add <files>`
5. Commit with a clear message, then `git push origin main`

## Commit message format

```
type(scope): short description
```

| Type | Use for |
|---|---|
| `feat` | a new feature |
| `fix` | a bug fix |
| `docs` | documentation only |
| `test` | adding or updating tests |
| `build` | Docker or dependency changes |
| `ci` | Jenkins or pipeline changes |
| `chore` | maintenance that doesn't change behaviour |

Keep messages under about 70 characters and write them in the present tense.

Examples:

- `fix(backend): handle empty alert list in stats summary`
- `docs: add troubleshooting table to README`

## Do not commit

- `.env` or any file with secrets
- `node_modules/`, `__pycache__/`, or dataset files
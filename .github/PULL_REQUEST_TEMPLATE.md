## Summary

## Compatibility and security boundaries

- [ ] Migration-sensitive runtime identifiers are preserved or an approved migration is documented.
- [ ] No secrets, access/QR links, certificates, production metadata, or unsanitized logs are included.
- [ ] Protocol/API, privilege, persistence, accounting, rollback and third-party-license boundaries were reviewed.

## Validation

- [ ] Full pytest/unittest and Ruff
- [ ] Bash syntax and ShellCheck for every tracked shell script
- [ ] Relevant Compose renders and image builds/checkers
- [ ] Documentation links and `git diff --check`

Commands/results:

## Rollback and pending gates

Describe state backup, compatibility impact, rollback, and any QEMU or production-only gate that remains pending.

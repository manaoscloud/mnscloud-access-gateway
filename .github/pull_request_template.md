## Summary

## Release note

<!-- Required: the MNSCloud merge gate refuses a PR without this block (contract: docs/release-notes.md
in the MNSCloud workspace). Keep ONE shape and delete the others:
A) user-visible change: the fields below, short text for the customer in pt-BR, en and es;
   `breaking` also needs action.pt-BR (what the customer must do).
B) another PR of a feature whose text is in a different repository's PR: only
   `feature-key: <task-slug>` and `lead: false`.
C) nothing a user notices (refactor, tests, CI, docs, dependencies): only `visibility: internal`.
Never write server names, IPs, host names, e-mails, paths, credentials, customers or vulnerability
details. -->

```text
visibility: internal
```

## Validation

- [ ] `deno fmt --check`, `deno lint`, `deno task check`, `deno task test`
- [ ] `bash -n scripts/*.sh scripts/lib/*.sh` and `shellcheck -x scripts/*.sh scripts/lib/*.sh`
- [ ] Policy rules changed: fixtures in `tests/fixtures/classifier.json` cover the new rules

## Security

- [ ] No secrets, customer data, private topology, or production credentials
- [ ] Workers keep: own network namespace, dynamic user, no capabilities, `--allow-net=<device>` only
- [ ] Unknown input still fails closed (write_risky); redaction still runs before anything leaves the worker

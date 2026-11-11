# Contributing

Changes enter through pull requests reviewed by the maintainers; CI must pass (format, lint, type
check, tests with the hostile SSH device and the RouterOS API mock, ShellCheck, secret guard and the
shared security scan). External contributors fork the repository and open a pull request.

- Policy rules (`rules/*.json`) are data: every new or changed rule needs fixtures in
  `tests/fixtures/classifier.json`, and anything not recognized must stay `unknown` (fail-closed).
- Redaction patterns need fixtures in `tests/fixtures/redaction.json`; the tests split each fixture
  at every position, so a pattern must survive chunked output.
- Dependencies are vendored (`node_modules/`, `deno.lock`, `--cached-only` at runtime). Adding one
  needs a maintainer decision; update with `deno install` and commit the result.
- Keep examples generic; never include real addresses, device configurations or credentials.

Payment for contributions requires an explicit written agreement and is never implied by opening a
pull request.

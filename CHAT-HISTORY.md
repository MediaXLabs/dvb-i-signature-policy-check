# Project conversation history

This file summarizes the decisions and project changes made in the related
Copilot chat, so they can be reviewed alongside the source.

## 2026-11-13

- Set up the PHP DVB-I SignaturePolicy host checker as a Git project, added
  GitHub Actions PHP syntax linting, and published the initial public repository:
  [paulhiggs/dvb-i-signature-policy-check](https://github.com/paulhiggs/dvb-i-signature-policy-check).
- Replaced the initial MIT license with BSD 3-Clause.
- Added GitHub Copilot credits to the PHP source and README.
- Removed the `DVB_I_ALLOWED_TARGETS` allowlist. The checker accepts DNS
  hostnames resolving only to public IP addresses; the README warns operators
  to restrict access and consider rate limiting.
- Changed policy validation so every `CAFingerprint` must match a CA certificate
  in the host's presented TLS chain.
- Changed `SubjectConstraint` validation so every listed `CN` must match a
  common name in the host certificate's subject.
- Set HTTP 200 for successful checks, and enforcement-based failure codes for
  certificate mismatches and TLS connection failures: `required` -> 403,
  `warn` -> 409, and `vendor` -> 422.
- Made enforcement values and hexadecimal fingerprint digits case-insensitive.

## 2026-11-16

- Extracted the host and SignaturePolicy validation into
  [signature-policy-checker.php](./signature-policy-checker.php), callable
  independently of HTTP POST handling with
  `checkSignaturePolicy($target, $policyXml)`.
- The checker returns a result array with `result`, `enforcement`, and
  `message`, plus optional connection diagnostics in `detail`. The HTTP
  endpoint maps those results to its response codes.
- Documented the standalone API in the README and updated CI to lint both PHP
  files.
- PHP syntax checks for both files and standalone checker smoke tests passed.
- Commit `c5a001b` contains the refactor. Pushing it failed because GitHub was
  unreachable; at the time of this note, local `main` was one commit ahead of
  `origin/main`. A later push succeeded with commit `7e11601`.

## Ongoing history

For future project work, append a concise, dated entry summarizing the request,
decisions, code/documentation changes, validation, and commit/push outcome.

## 2026-11-16 (tests)

- Added live integration tests for successful and failing `checkSignaturePolicy()`
  results, including `example.com`, `www.wikipedia.org`, and `dvb.org`.
- Added Linux and Windows PowerShell test runners and documented the network and
  PHP extension requirements.
- PHP syntax checks passed. Both runners completed with 3 tests passing and no
  failures; live-host cases were skipped because outbound TLS connections were
  unavailable in the test environment.
- Committed and pushed these changes in `ba64106`.

## 2026-11-18 (error reporting, Claude Code)

- Added optional A177r8 clause 7.6.2.5 error reporting. `checkSignaturePolicy()`
  takes a third argument with zero or more reporting endpoints, either as an
  array or a comma-separated string. The HTTP endpoint accepts the same values
  in `reportingEndpoints`, with at most 10 endpoints.
- Unsuccessful validations of a parsed policy are POSTed as
  `application/reports+json` W3C Reporting API reports with type
  `signature-verification-issue`, destination `dvbi-signature-validation`, and
  a body holding `policy`, plus `vendor-action` for `vendor` enforcement.
  Invalid targets and policies are not reported. Delivery outcomes are returned
  in `reports`.
- Reporting endpoints must be HTTPS URLs whose hostnames resolve only to public
  IP addresses. Each connection is made to the address that was checked.
- `policyId` is now required, matching the schema, because reports need it.
- The README now documents the feature and credits Claude. Tests were added
  for the report format, endpoint parsing, unsafe endpoints, and live delivery.
  All 16 tests passed, including the live cases.
- Committed and pushed these changes in `c49c9e2`.

# DVB-I SignaturePolicy host checker

A standalone PHP 8.1+ HTTP endpoint that checks an HTTPS host against one
DVB-I `SignaturePolicy` (A177r8). Requires the PHP OpenSSL and DOM extensions.

## Run

Start PHP's built-in server from this directory:

```sh
php -S 127.0.0.1:8080
```

POST JSON to `http://127.0.0.1:8080/dvb-i-signature-policy-check.php`:

```json
{
  "target": "https://service.example/",
  "signaturePolicy": "<SignaturePolicy xmlns=\"urn:dvb:metadata:servicediscovery-types:2026\" policyId=\"urn:example:policy\"><Enforcement>required</Enforcement><TrustAnchor><CAFingerprint algorithm=\"sha256\">00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f</CAFingerprint></TrustAnchor></SignaturePolicy>"
}
```

Replace the example fingerprint with the policy's actual CA certificate
fingerprint. A host-only request may include `port`; it defaults to 443. The
body may use either `target` (URL or hostname with optional port), or `host`
and optional `port`, together with the XML policy string.

The endpoint accepts any DNS hostname that resolves only to public IP addresses.
It verifies the TLS hostname and system certificate chain, then requires every
`CAFingerprint` in the policy to match a CA certificate in the host's TLS
certificate chain. If `SubjectConstraint` is present, every listed `CN` must
match a common name in the host certificate's subject. Successful validation
returns HTTP 200. A certificate mismatch or TLS connection failure returns
HTTP 403 for `required`, 409 for `warn`, or 422 for `vendor`. Other request and
destination errors retain their own status codes.
Enforcement values and hexadecimal fingerprint digits are accepted without
regard to letter case. The `policyId` attribute is required, as in the A177r8
schema.

## Optional error reporting (A177r8 clause 7.6.2.5)

A request may name zero or more reporting endpoints in `reportingEndpoints`,
either as a comma-separated string or as an array of URL strings:

```json
{
  "target": "https://service.example/",
  "signaturePolicy": "<SignaturePolicy ...>...</SignaturePolicy>",
  "reportingEndpoints": "https://reports.example/dvbi, https://backup.example/dvbi"
}
```

When a validation of a parsed policy does not succeed (`Fail-Required`,
`Fail-Warn`, `Fail-Vendor`, `No connection`, or `Non-Public-Target`), the
checker sends an HTTP `POST` to each endpoint with
`Content-Type: application/reports+json`. The body is a W3C Reporting API
report list in the format that clause 7.6.2.5 requires:

```json
[
  {
    "type": "signature-verification-issue",
    "url": "https://service.example:443",
    "user_agent": "dvb-i-signature-policy-check/1.0",
    "destination": "dvbi-signature-validation",
    "timestamp": 1795000000000,
    "attempts": 0,
    "age": 0,
    "body": { "policy": "urn:example:policy" }
  }
]
```

`body.vendor-action` is added only when the policy's enforcement is `vendor`.
The checker validates the TLS certificate chain rather than a JWS signature, so
`body.signature-present` is never sent. Successful checks and invalid requests
(`Invalid-Target`, `Invalid-Policy`) are not reported.

Reporting endpoints must be HTTPS URLs whose hostnames resolve only to public
IP addresses. Each report is sent once, with a 5 second timeout. The HTTP
endpoint accepts at most 10 reporting endpoints. When any endpoints are given,
the JSON response includes a `reports` array with each endpoint's `delivered`
flag, HTTP `status`, and `error`. Failed deliveries are also written to the PHP
error log. A delivery failure never changes the response status code.

The public-IP check rejects destinations that resolve to private or reserved
addresses. Since the endpoint can initiate TLS connections to any public host,
restrict access to it and consider rate limiting before exposing it.

## Tests

The tests make live TLS requests to `example.com`, `www.wikipedia.org`, and
`dvb.org`, so an internet connection is needed for the live cases. They derive
CA fingerprints from each verified certificate chain, then exercise successful
checks, enforcement-specific fingerprint failures, subject-name mismatches,
invalid inputs, and an unresolvable host. They also cover the clause 7.6.2.5
report format, parsing of reporting endpoints, refusal of unsafe endpoints, and
a live report `POST` to `example.com`. Live cases are reported as skipped
when the host cannot be reached. PHP CLI with the DOM and OpenSSL extensions is
required.

Run on Linux:

```sh
./tests/run-tests.sh
```

Run on Windows PowerShell:

```powershell
.\tests\run-tests.ps1
```

## Use the checker without HTTP

The policy check is available independently from the POST endpoint:

```php
require_once __DIR__ . '/signature-policy-checker.php';

$result = checkSignaturePolicy('https://service.example/', $signaturePolicyXml);
if ($result['result'] === 'OK') {
    // The host matches the policy.
}

// Optional: report failures to zero or more endpoints (array or comma-separated string).
$result = checkSignaturePolicy(
    'https://service.example/',
    $signaturePolicyXml,
    ['https://reports.example/dvbi', 'https://backup.example/dvbi']
);
foreach ($result['reports'] as $report) {
    // $report['endpoint'], $report['delivered'], $report['status'], $report['error']
}
```

`checkSignaturePolicy()` returns an array with `result`, `enforcement`, and
`message` values, plus optional connection diagnostics in `detail`. Results
include `OK`, `Fail-Required`, `Fail-Warn`, `Fail-Vendor`, `No connection`,
`Non-Public-Target`, `Invalid-Target`, `Invalid-Policy`, and
`Invalid-Reporting-Endpoint`. The `reports` value lists one delivery outcome per
reporting endpoint, and is empty when nothing was reported.
The HTTP endpoint maps those results to HTTP status codes; callers outside HTTP
can handle them directly.

## Credits

Developed with assistance from GitHub Copilot and Claude (Anthropic) via
Claude Code. Claude added the A177r8 clause 7.6.2.5 error reporting.

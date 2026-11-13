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
regard to letter case.

The public-IP check rejects destinations that resolve to private or reserved
addresses. Since the endpoint can initiate TLS connections to any public host,
restrict access to it and consider rate limiting before exposing it.

## Credits

Developed with assistance from GitHub Copilot.

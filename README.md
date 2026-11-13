# DVB-I SignaturePolicy host checker

A standalone PHP 8.1+ HTTP endpoint that checks an HTTPS host against one
DVB-I `SignaturePolicy` (A177r8). Requires the PHP OpenSSL and DOM extensions.

## Run

Set an exact hostname-and-port allowlist before exposing the endpoint:

```text
DVB_I_ALLOWED_TARGETS=service.example:443,other.example:8443
```

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

The endpoint verifies the TLS hostname and system certificate chain, then
checks the policy's CA fingerprint and optional certificate subject CN. A
match returns HTTP 200; malformed input, a policy mismatch, disallowed
destinations, and connection failures return non-200 status codes.

The exact destination allowlist and public-IP check protect against server-side
request forgery. Restrict access to this endpoint as well.

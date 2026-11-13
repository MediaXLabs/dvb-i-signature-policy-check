<?php
declare(strict_types=1);

// Developed with assistance from GitHub Copilot.

const MAX_BODY_BYTES = 16384;
const CONNECT_TIMEOUT_SECONDS = 5;

function respond(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status' => $status, 'message' => $message], JSON_UNESCAPED_SLASHES);
    exit;
}

function parseTarget(array $request): array
{
    if (isset($request['target'])) {
        if (!is_string($request['target']) || isset($request['host']) || isset($request['port'])) {
            respond(400, 'Provide either target or host and port.');
        }
        $target = trim($request['target']);
        $url = parse_url(str_contains($target, '://') ? $target : 'https://' . $target);
        if ($url === false || (isset($url['scheme']) && strtolower($url['scheme']) !== 'https')
            || isset($url['user']) || isset($url['pass']) || isset($url['fragment'])) {
            respond(400, 'Target must be an HTTPS URL or hostname with an optional port.');
        }
        $host = $url['host'] ?? '';
        $port = $url['port'] ?? 443;
    } else {
        $host = $request['host'] ?? '';
        $port = $request['port'] ?? 443;
    }

    if (!is_string($host) || !is_int($port) && !(is_string($port) && ctype_digit($port))) {
        respond(400, 'Invalid host or port.');
    }
    $host = strtolower(rtrim($host, '.'));
    $port = (int) $port;
    if ($host === '' || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
        || filter_var($host, FILTER_VALIDATE_IP) !== false || $port < 1 || $port > 65535) {
        respond(400, 'A DNS hostname and valid port are required.');
    }

    return [$host, $port];
}

function parsePolicy(string $xml): array
{
    if (str_contains($xml, '<!DOCTYPE')) {
        respond(400, 'DOCTYPE is not allowed in a SignaturePolicy.');
    }
    $document = new DOMDocument();
    $document->resolveExternals = false;
    $document->substituteEntities = false;
    if (!@$document->loadXML($xml, LIBXML_NONET | LIBXML_NOBLANKS)) {
        respond(400, 'Invalid SignaturePolicy XML.');
    }
    $policies = $document->getElementsByTagNameNS('*', 'SignaturePolicy');
    if ($policies->length !== 1) {
        respond(400, 'Provide exactly one DVB-I SignaturePolicy element.');
    }
    $policy = $policies->item(0);
    $enforcement = trim($policy->getElementsByTagNameNS('*', 'Enforcement')->item(0)?->textContent ?? '');
    if (!in_array($enforcement, ['required', 'warn', 'vendor'], true)) {
        respond(400, 'SignaturePolicy has an invalid Enforcement value.');
    }

    $fingerprints = [];
    foreach ($policy->getElementsByTagNameNS('*', 'CAFingerprint') as $fingerprint) {
        $algorithm = strtolower(str_replace('-', '', trim($fingerprint->getAttribute('algorithm'))));
        if (!in_array($algorithm, ['sha1', 'sha256', 'sha384', 'sha512'], true)) {
            respond(400, 'SignaturePolicy uses an unsupported CA fingerprint algorithm.');
        }
        $formattedFingerprint = trim($fingerprint->textContent);
        if (!preg_match('/\A[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})*\z/', $formattedFingerprint)) {
            respond(400, 'SignaturePolicy contains an invalid CA fingerprint.');
        }
        $hex = strtolower(str_replace(':', '', $formattedFingerprint));
        if (strlen($hex) !== strlen(hash($algorithm, '', false))) {
            respond(400, 'SignaturePolicy contains an invalid CA fingerprint.');
        }
        $fingerprints[] = [$algorithm, $hex];
    }
    if ($fingerprints === []) {
        respond(400, 'SignaturePolicy must contain at least one CAFingerprint.');
    }

    $commonNames = [];
    foreach ($policy->getElementsByTagNameNS('*', 'SubjectConstraint') as $constraint) {
        foreach ($constraint->getElementsByTagNameNS('*', 'CN') as $commonName) {
            $value = trim($commonName->textContent);
            if ($value !== '') {
                $commonNames[] = $value;
            }
        }
    }

    return [$fingerprints, $commonNames];
}

function resolvePublicAddresses(string $host): array
{
    $records = @dns_get_record($host, DNS_A | DNS_AAAA);
    if (!is_array($records)) {
        respond(502, 'The target hostname could not be resolved.');
    }
    $addresses = [];
    foreach ($records as $record) {
        $address = $record['ip'] ?? $record['ipv6'] ?? null;
        if ($address === null) {
            continue;
        }
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            respond(403, 'The target resolves to a non-public IP address.');
        }
        $addresses[] = $address;
    }
    if ($addresses === []) {
        respond(502, 'The target hostname has no A or AAAA records.');
    }
    return array_values(array_unique($addresses));
}

function isCaCertificate($certificate): bool
{
    $details = openssl_x509_parse($certificate);
    return is_array($details)
        && isset($details['extensions']['basicConstraints'])
        && str_contains($details['extensions']['basicConstraints'], 'CA:TRUE');
}

function certificateMatchesPolicy($certificate, array $fingerprints): bool
{
    if (!isCaCertificate($certificate)) {
        return false;
    }
    foreach ($fingerprints as [$algorithm, $expected]) {
        $actual = openssl_x509_fingerprint($certificate, $algorithm);
        if ($actual !== false && hash_equals($expected, strtolower($actual))) {
            return true;
        }
    }
    return false;
}

function trustedCaFiles(): array
{
    $locations = openssl_get_cert_locations();
    $files = [$locations['ini_cafile'] ?? '', $locations['default_cert_file'] ?? ''];
    return array_values(array_unique(array_filter($files, 'is_file')));
}

function policyMatches($stream, array $fingerprints, array $commonNames): bool
{
    $context = stream_context_get_params($stream)['options']['ssl'] ?? [];
    $chain = $context['peer_certificate_chain'] ?? [];
    if ($chain === []) {
        return false;
    }

    $leafDetails = openssl_x509_parse($chain[0]);
    $certificateNames = $leafDetails['subject']['CN'] ?? [];
    if (!is_array($certificateNames)) {
        $certificateNames = [$certificateNames];
    }
    if ($commonNames !== [] && array_intersect($commonNames, $certificateNames) === []) {
        return false;
    }

    foreach ($chain as $certificate) {
        if (certificateMatchesPolicy($certificate, $fingerprints)) {
            return true;
        }
    }
    foreach (trustedCaFiles() as $file) {
        $bundle = @file_get_contents($file);
        if ($bundle === false) {
            continue;
        }
        preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $bundle, $matches);
        foreach ($matches[0] as $pem) {
            $certificate = openssl_x509_read($pem);
            if ($certificate !== false && certificateMatchesPolicy($certificate, $fingerprints)) {
                return true;
            }
        }
    }
    return false;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    respond(405, 'Use POST with a JSON request body.');
}

$body = file_get_contents('php://input', false, null, 0, MAX_BODY_BYTES + 1);
if ($body === false || strlen($body) > MAX_BODY_BYTES) {
    respond(413, 'Request body is too large.');
}
$request = json_decode($body, true);
if (!is_array($request) || !isset($request['signaturePolicy']) || !is_string($request['signaturePolicy'])) {
    respond(400, 'JSON body must include signaturePolicy as a DVB-I XML string.');
}

[$host, $port] = parseTarget($request);
$allowedTargets = array_filter(array_map('trim', explode(',', getenv('DVB_I_ALLOWED_TARGETS') ?: '')));
if ($allowedTargets === []) {
    respond(503, 'Configure DVB_I_ALLOWED_TARGETS before accepting requests.');
}
$authority = $host . ':' . $port;
if (!in_array($authority, array_map('strtolower', $allowedTargets), true)) {
    respond(403, 'Target is not in the configured allowlist.');
}

[$fingerprints, $commonNames] = parsePolicy($request['signaturePolicy']);
$addresses = resolvePublicAddresses($host);
$lastError = '';
foreach ($addresses as $address) {
    $endpoint = str_contains($address, ':') ? "tls://[$address]:$port" : "tls://$address:$port";
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $host,
            'SNI_enabled' => true,
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
        ],
    ]);
    $stream = @stream_socket_client(
        $endpoint,
        $errorCode,
        $errorMessage,
        CONNECT_TIMEOUT_SECONDS,
        STREAM_CLIENT_CONNECT,
        $context
    );
    if ($stream === false) {
        $lastError = $errorMessage;
        continue;
    }
    $matches = policyMatches($stream, $fingerprints, $commonNames);
    fclose($stream);
    if ($matches) {
        respond(200, 'SignaturePolicy matches the target host and TLS certificate.');
    }
    respond(403, 'Target certificate does not match the SignaturePolicy.');
}

error_log('DVB-I policy check failed to connect: ' . $lastError);
respond(502, 'Could not establish a verified TLS connection to the target.');

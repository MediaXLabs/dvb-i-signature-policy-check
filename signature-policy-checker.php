<?php
declare(strict_types=1);

const SIGNATURE_POLICY_CONNECT_TIMEOUT_SECONDS = 5;
const SIGNATURE_POLICY_USER_AGENT = 'dvb-i-signature-policy-check/1.0';
const SIGNATURE_POLICY_REPORT_DESTINATION = 'dvbi-signature-validation';
const SIGNATURE_POLICY_REPORT_TYPE = 'signature-verification-issue';

function signaturePolicyResult(
    string $result,
    ?string $enforcement,
    string $message,
    ?string $detail = null
): array
{
    return [
        'result' => $result,
        'enforcement' => $enforcement,
        'message' => $message,
        'detail' => $detail,
    ];
}

function parseSignaturePolicyTarget(string $target): array
{
    $target = trim($target);
    $url = parse_url(str_contains($target, '://') ? $target : 'https://' . $target);
    if ($url === false || (isset($url['scheme']) && strtolower($url['scheme']) !== 'https')
        || isset($url['user']) || isset($url['pass']) || isset($url['fragment'])) {
        throw new InvalidArgumentException('Target must be an HTTPS URL or hostname with an optional port.');
    }

    $host = strtolower(rtrim($url['host'] ?? '', '.'));
    $port = $url['port'] ?? 443;
    if ($host === '' || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
        || filter_var($host, FILTER_VALIDATE_IP) !== false || $port < 1 || $port > 65535) {
        throw new InvalidArgumentException('A DNS hostname and valid port are required.');
    }

    return [$host, $port];
}

function parseSignaturePolicyXml(string $xml): array
{
    if (str_contains($xml, '<!DOCTYPE')) {
        throw new InvalidArgumentException('DOCTYPE is not allowed in a SignaturePolicy.');
    }
    $document = new DOMDocument();
    $document->resolveExternals = false;
    $document->substituteEntities = false;
    if (!@$document->loadXML($xml, LIBXML_NONET | LIBXML_NOBLANKS)) {
        throw new InvalidArgumentException('Invalid SignaturePolicy XML.');
    }
    $policies = $document->getElementsByTagNameNS('*', 'SignaturePolicy');
    if ($policies->length !== 1) {
        throw new InvalidArgumentException('Provide exactly one DVB-I SignaturePolicy element.');
    }
    $policy = $policies->item(0);
    $enforcement = strtolower(trim($policy->getElementsByTagNameNS('*', 'Enforcement')->item(0)?->textContent ?? ''));
    if (!in_array($enforcement, ['required', 'warn', 'vendor'], true)) {
        throw new InvalidArgumentException('SignaturePolicy has an invalid Enforcement value.');
    }
    $policyId = trim($policy->getAttribute('policyId'));
    if ($policyId === '') {
        throw new InvalidArgumentException('SignaturePolicy must have a policyId attribute.');
    }

    $fingerprints = [];
    foreach ($policy->getElementsByTagNameNS('*', 'CAFingerprint') as $fingerprint) {
        $algorithm = strtolower(str_replace('-', '', trim($fingerprint->getAttribute('algorithm'))));
        if (!in_array($algorithm, ['sha1', 'sha256', 'sha384', 'sha512'], true)) {
            throw new InvalidArgumentException('SignaturePolicy uses an unsupported CA fingerprint algorithm.');
        }
        $formattedFingerprint = trim($fingerprint->textContent);
        if (!preg_match('/\A[0-9a-f]{2}(?::[0-9a-f]{2})*\z/i', $formattedFingerprint)) {
            throw new InvalidArgumentException('SignaturePolicy contains an invalid CA fingerprint.');
        }
        $hex = strtolower(str_replace(':', '', $formattedFingerprint));
        if (strlen($hex) !== strlen(hash($algorithm, '', false))) {
            throw new InvalidArgumentException('SignaturePolicy contains an invalid CA fingerprint.');
        }
        $fingerprints[] = [$algorithm, $hex];
    }
    if ($fingerprints === []) {
        throw new InvalidArgumentException('SignaturePolicy must contain at least one CAFingerprint.');
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

    return [$enforcement, $fingerprints, $commonNames, $policyId];
}

function resolveSignaturePolicyAddresses(string $host): array
{
    $records = @dns_get_record($host, DNS_A | DNS_AAAA);
    if (!is_array($records)) {
        return [];
    }
    $addresses = [];
    foreach ($records as $record) {
        $address = $record['ip'] ?? $record['ipv6'] ?? null;
        if ($address === null) {
            continue;
        }
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            throw new DomainException('The target resolves to a non-public IP address.');
        }
        $addresses[] = $address;
    }
    return array_values(array_unique($addresses));
}

function signaturePolicyIsCaCertificate($certificate): bool
{
    $details = openssl_x509_parse($certificate);
    return is_array($details)
        && isset($details['extensions']['basicConstraints'])
        && str_contains($details['extensions']['basicConstraints'], 'CA:TRUE');
}

function signaturePolicyCertificateMatchesFingerprint($certificate, string $algorithm, string $expected): bool
{
    if (!signaturePolicyIsCaCertificate($certificate)) {
        return false;
    }
    $actual = openssl_x509_fingerprint($certificate, $algorithm);
    return $actual !== false && hash_equals($expected, strtolower($actual));
}

function signaturePolicyMatches($stream, array $fingerprints, array $commonNames): bool
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
    foreach ($commonNames as $commonName) {
        if (!in_array($commonName, $certificateNames, true)) {
            return false;
        }
    }

    foreach ($fingerprints as [$algorithm, $expected]) {
        $found = false;
        foreach ($chain as $certificate) {
            if (signaturePolicyCertificateMatchesFingerprint($certificate, $algorithm, $expected)) {
                $found = true;
                break;
            }
        }
        if (!$found) {
            return false;
        }
    }
    return true;
}

/**
 * Builds one W3C Reporting API report (clause 2.1.3) carrying the values that
 * DVB A177r8 clause 7.6.2.5 requires for a signature validation issue.
 */
function buildSignaturePolicyReport(
    string $url,
    string $policyId,
    string $enforcement,
    string $message,
    ?int $timestamp = null
): array {
    $body = ['policy' => $policyId];
    if ($enforcement === 'vendor') {
        $body['vendor-action'] = 'Signature policy validation failed and was reported: ' . $message;
    }

    return [
        'type' => SIGNATURE_POLICY_REPORT_TYPE,
        'url' => $url,
        'user_agent' => SIGNATURE_POLICY_USER_AGENT,
        'destination' => SIGNATURE_POLICY_REPORT_DESTINATION,
        'timestamp' => $timestamp ?? (int) floor(microtime(true) * 1000),
        'attempts' => 0,
        'age' => 0,
        'body' => $body,
    ];
}

/**
 * Accepts a comma-separated string or an array of strings and returns the
 * non-empty, de-duplicated reporting endpoint URLs.
 */
function parseSignaturePolicyReportingEndpoints(string|array $endpoints): array
{
    if (is_string($endpoints)) {
        $endpoints = explode(',', $endpoints);
    }
    $parsed = [];
    foreach ($endpoints as $endpoint) {
        if (!is_string($endpoint)) {
            throw new InvalidArgumentException('Reporting endpoints must be strings.');
        }
        $endpoint = trim($endpoint);
        if ($endpoint !== '') {
            $parsed[] = $endpoint;
        }
    }
    return array_values(array_unique($parsed));
}

/**
 * POSTs the reports to one endpoint as application/reports+json. The endpoint
 * must be an HTTPS URL resolving only to public IP addresses; the connection is
 * made to the resolved address so DNS cannot be re-pointed between check and use.
 */
function sendSignaturePolicyReport(string $endpoint, array $reports): array
{
    $outcome = ['endpoint' => $endpoint, 'delivered' => false, 'status' => null, 'error' => null];

    $url = parse_url($endpoint);
    if ($url === false || strtolower($url['scheme'] ?? '') !== 'https' || !isset($url['host'])
        || isset($url['user']) || isset($url['pass'])) {
        $outcome['error'] = 'Reporting endpoint must be an HTTPS URL.';
        return $outcome;
    }
    $host = strtolower(rtrim($url['host'], '.'));
    $port = $url['port'] ?? 443;
    if (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
        || filter_var($host, FILTER_VALIDATE_IP) !== false) {
        $outcome['error'] = 'Reporting endpoint must use a DNS hostname.';
        return $outcome;
    }

    try {
        $addresses = resolveSignaturePolicyAddresses($host);
    } catch (DomainException $exception) {
        $outcome['error'] = 'Reporting endpoint resolves to a non-public IP address.';
        return $outcome;
    }
    if ($addresses === []) {
        $outcome['error'] = 'Reporting endpoint hostname has no A or AAAA records.';
        return $outcome;
    }

    $payload = json_encode($reports, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $path = ($url['path'] ?? '') === '' ? '/' : $url['path'];
    if (isset($url['query'])) {
        $path .= '?' . $url['query'];
    }
    $hostHeader = $port === 443 ? $host : "$host:$port";
    $request = "POST $path HTTP/1.1\r\n"
        . "Host: $hostHeader\r\n"
        . 'User-Agent: ' . SIGNATURE_POLICY_USER_AGENT . "\r\n"
        . "Content-Type: application/reports+json\r\n"
        . 'Content-Length: ' . strlen($payload) . "\r\n"
        . "Connection: close\r\n\r\n"
        . $payload;

    foreach ($addresses as $address) {
        $socket = str_contains($address, ':') ? "tls://[$address]:$port" : "tls://$address:$port";
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'peer_name' => $host,
                'SNI_enabled' => true,
            ],
        ]);
        $stream = @stream_socket_client(
            $socket,
            $errorCode,
            $errorMessage,
            SIGNATURE_POLICY_CONNECT_TIMEOUT_SECONDS,
            STREAM_CLIENT_CONNECT,
            $context
        );
        if ($stream === false) {
            $outcome['error'] = $errorMessage !== '' ? $errorMessage : 'Could not connect to the reporting endpoint.';
            continue;
        }
        stream_set_timeout($stream, SIGNATURE_POLICY_CONNECT_TIMEOUT_SECONDS);
        $written = @fwrite($stream, $request);
        $statusLine = $written === strlen($request) ? fgets($stream) : false;
        fclose($stream);
        if ($statusLine === false || !preg_match('#\AHTTP/\d(?:\.\d)? (\d{3})#', $statusLine, $match)) {
            $outcome['error'] = 'The reporting endpoint did not return a valid HTTP response.';
            continue;
        }
        $outcome['status'] = (int) $match[1];
        $outcome['delivered'] = $outcome['status'] >= 200 && $outcome['status'] < 300;
        $outcome['error'] = $outcome['delivered'] ? null : "The reporting endpoint returned HTTP {$outcome['status']}.";
        return $outcome;
    }
    return $outcome;
}

/**
 * Checks the target against the SignaturePolicy. When validation of a parsed
 * policy does not succeed, a report is POSTed to each reporting endpoint
 * according to DVB A177r8 clause 7.6.2.5, and the delivery outcomes are
 * returned in the result's 'reports' value.
 *
 * @param string|string[] $reportingEndpoints Comma-separated string or array of HTTPS URLs.
 */
function checkSignaturePolicy(string $target, string $policyXml, string|array $reportingEndpoints = []): array
{
    try {
        $endpoints = parseSignaturePolicyReportingEndpoints($reportingEndpoints);
    } catch (InvalidArgumentException $exception) {
        $result = signaturePolicyResult('Invalid-Reporting-Endpoint', null, $exception->getMessage());
        $result['reports'] = [];
        return $result;
    }

    $result = validateSignaturePolicy($target, $policyXml, $policyId);
    $result['reports'] = [];
    if ($result['result'] === 'OK' || $policyId === null || $endpoints === []) {
        return $result;
    }

    $reportUrl = str_contains(trim($target), '://') ? trim($target) : 'https://' . trim($target);
    $report = buildSignaturePolicyReport($reportUrl, $policyId, $result['enforcement'], $result['message']);
    foreach ($endpoints as $endpoint) {
        $result['reports'][] = sendSignaturePolicyReport($endpoint, [$report]);
    }
    return $result;
}

function validateSignaturePolicy(string $target, string $policyXml, ?string &$policyId): array
{
    $policyId = null;
    try {
        [$host, $port] = parseSignaturePolicyTarget($target);
    } catch (InvalidArgumentException $exception) {
        return signaturePolicyResult('Invalid-Target', null, $exception->getMessage());
    }

    try {
        [$enforcement, $fingerprints, $commonNames, $parsedPolicyId] = parseSignaturePolicyXml($policyXml);
        $policyId = $parsedPolicyId;
    } catch (InvalidArgumentException $exception) {
        return signaturePolicyResult('Invalid-Policy', null, $exception->getMessage());
    }

    try {
        $addresses = resolveSignaturePolicyAddresses($host);
    } catch (DomainException $exception) {
        return signaturePolicyResult('Non-Public-Target', $enforcement, $exception->getMessage());
    }
    if ($addresses === []) {
        return signaturePolicyResult('No connection', $enforcement, 'The target hostname has no A or AAAA records.');
    }

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
            SIGNATURE_POLICY_CONNECT_TIMEOUT_SECONDS,
            STREAM_CLIENT_CONNECT,
            $context
        );
        if ($stream === false) {
            $lastError = $errorMessage;
            continue;
        }
        $matches = signaturePolicyMatches($stream, $fingerprints, $commonNames);
        fclose($stream);
        if (!$matches) {
            return signaturePolicyResult(
                'Fail-' . ucfirst($enforcement),
                $enforcement,
                'Target certificate does not match the SignaturePolicy.'
            );
        }
        return signaturePolicyResult('OK', $enforcement, 'SignaturePolicy matches the target host and TLS certificate.');
    }

    $message = 'Could not establish a verified TLS connection to the target.';
    return signaturePolicyResult('No connection', $enforcement, $message, $lastError);
}

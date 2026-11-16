<?php
declare(strict_types=1);

// Developed with assistance from GitHub Copilot.

require_once __DIR__ . '/signature-policy-checker.php';

const MAX_BODY_BYTES = 16384;

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

function policyFailureStatus(string $enforcement): int
{
    return match ($enforcement) {
        'required' => 403,
        'warn' => 409,
        'vendor' => 422,
    };
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
$result = checkSignaturePolicy("https://$host:$port", $request['signaturePolicy']);
if ($result['result'] === 'No connection') {
    error_log('DVB-I policy check failed to connect: ' . ($result['detail'] ?: $result['message']));
}
$status = match ($result['result']) {
    'OK' => 200,
    'Fail-Required' => 403,
    'Fail-Warn' => 409,
    'Fail-Vendor' => 422,
    'No connection' => policyFailureStatus($result['enforcement']),
    'Invalid-Target', 'Invalid-Policy' => 400,
    'Non-Public-Target' => 403,
};
respond($status, $result['message']);

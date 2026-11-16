<?php
declare(strict_types=1);

require_once __DIR__ . '/../signature-policy-checker.php';

const TEST_HOSTS = [
    'https://example.com/',
    'https://www.wikipedia.org/',
    'https://dvb.org/',
];

$passed = 0;
$failed = 0;
$hostPolicies = [];

class TestSkippedException extends RuntimeException
{
}

function runTest(string $name, callable $test): void
{
    global $passed, $failed;
    try {
        $test();
        $passed++;
        echo "PASS: $name\n";
    } catch (TestSkippedException $exception) {
        echo "SKIP: $name - {$exception->getMessage()}\n";
    } catch (Throwable $exception) {
        $failed++;
        fwrite(STDERR, "FAIL: $name - {$exception->getMessage()}\n");
    }
}

function expectResult(array $actual, string $expected): void
{
    if (($actual['result'] ?? null) !== $expected) {
        $message = $actual['message'] ?? 'No message returned';
        throw new RuntimeException("Expected $expected, got " . ($actual['result'] ?? 'unknown') . ": $message");
    }
}

function discoverHostPolicy(string $target): array
{
    $url = parse_url($target);
    if ($url === false || !isset($url['host'])) {
        throw new RuntimeException("Invalid test URL: $target");
    }
    $host = $url['host'];
    $port = $url['port'] ?? 443;
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
        "tls://$host:$port",
        $errorCode,
        $errorMessage,
        5,
        STREAM_CLIENT_CONNECT,
        $context
    );
    if ($stream === false) {
        throw new TestSkippedException("Could not connect to inspect TLS certificates: $errorMessage");
    }

    $chain = stream_context_get_params($stream)['options']['ssl']['peer_certificate_chain'] ?? [];
    fclose($stream);
    if ($chain === []) {
        throw new RuntimeException("The TLS server for $host did not provide a certificate chain");
    }

    $leafDetails = openssl_x509_parse($chain[0]);
    $commonNames = $leafDetails['subject']['CN'] ?? [];
    if (!is_array($commonNames)) {
        $commonNames = [$commonNames];
    }

    $fingerprints = [];
    foreach ($chain as $certificate) {
        $details = openssl_x509_parse($certificate);
        if (!is_array($details)
            || !isset($details['extensions']['basicConstraints'])
            || !str_contains($details['extensions']['basicConstraints'], 'CA:TRUE')) {
            continue;
        }
        $fingerprint = openssl_x509_fingerprint($certificate, 'sha256');
        if ($fingerprint !== false) {
            $fingerprints[] = implode(':', str_split(strtolower($fingerprint), 2));
        }
    }
    $fingerprints = array_values(array_unique($fingerprints));
    if ($fingerprints === []) {
        throw new RuntimeException("The TLS server for $host did not provide a CA certificate in its chain");
    }

    return [
        'fingerprints' => $fingerprints,
        'commonName' => $commonNames[0] ?? null,
    ];
}

function createPolicyXml(
    array $hostPolicy,
    string $enforcement,
    ?array $fingerprints = null,
    ?string $commonName = null,
    bool $uppercaseValues = false
): string {
    $fingerprints = $fingerprints ?? $hostPolicy['fingerprints'];
    if ($uppercaseValues) {
        $enforcement = strtoupper($enforcement);
        $fingerprints = array_map('strtoupper', $fingerprints);
    }

    $fingerprintElements = '';
    foreach ($fingerprints as $fingerprint) {
        $fingerprintElements .= '<CAFingerprint algorithm="sha256">'
            . htmlspecialchars($fingerprint, ENT_XML1 | ENT_QUOTES, 'UTF-8')
            . '</CAFingerprint>';
    }

    $subjectConstraint = '';
    if ($commonName !== null) {
        $subjectConstraint = '<SubjectConstraint><CN>'
            . htmlspecialchars($commonName, ENT_XML1 | ENT_QUOTES, 'UTF-8')
            . '</CN></SubjectConstraint>';
    }

    return '<SignaturePolicy xmlns="urn:dvb:metadata:servicediscovery-types:2026" policyId="urn:test:signature-policy">'
        . '<Enforcement>' . htmlspecialchars($enforcement, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</Enforcement>'
        . '<TrustAnchor>' . $fingerprintElements . '</TrustAnchor>'
        . $subjectConstraint
        . '</SignaturePolicy>';
}

runTest('Rejects an HTTP target', function (): void {
    $result = checkSignaturePolicy('http://example.com/', '<SignaturePolicy/>');
    expectResult($result, 'Invalid-Target');
});

runTest('Rejects malformed policy XML', function (): void {
    $result = checkSignaturePolicy('https://example.com/', '<SignaturePolicy>');
    expectResult($result, 'Invalid-Policy');
});

foreach (TEST_HOSTS as $index => $target) {
    runTest("Accepts the live TLS certificate for $target", function () use ($index, $target, &$hostPolicies): void {
        $hostPolicy = discoverHostPolicy($target);
        $policyXml = createPolicyXml(
            $hostPolicy,
            'required',
            null,
            $hostPolicy['commonName'],
            $index === 0
        );
        $result = checkSignaturePolicy($target, $policyXml);
        if ($result['result'] === 'No connection') {
            throw new TestSkippedException($result['message']);
        }
        expectResult($result, 'OK');
        $hostPolicies[$target] = $hostPolicy;
    });
}

runTest('Returns No connection for an unresolvable target', function (): void {
    $policyXml = createPolicyXml(['fingerprints' => [str_repeat('00:', 31) . '00']], 'warn');
    $result = checkSignaturePolicy('https://signature-policy-test.invalid/', $policyXml);
    expectResult($result, 'No connection');
    if ($result['enforcement'] !== 'warn') {
        throw new RuntimeException('The no-connection result did not preserve the policy enforcement value');
    }
});

if (isset($hostPolicies[TEST_HOSTS[0]])) {
    $hostPolicy = $hostPolicies[TEST_HOSTS[0]];
    $wrongFingerprint = [str_repeat('00:', 31) . '00'];

    foreach (['required' => 'Fail-Required', 'warn' => 'Fail-Warn', 'vendor' => 'Fail-Vendor'] as $enforcement => $expected) {
        runTest("Returns $expected for a fingerprint mismatch", function () use ($hostPolicy, $enforcement, $expected, $wrongFingerprint): void {
            $policyXml = createPolicyXml($hostPolicy, $enforcement, $wrongFingerprint);
            $result = checkSignaturePolicy(TEST_HOSTS[0], $policyXml);
            if ($result['result'] === 'No connection') {
                throw new TestSkippedException($result['message']);
            }
            expectResult($result, $expected);
        });
    }

    if ($hostPolicy['commonName'] !== null) {
        runTest('Rejects a SubjectConstraint CN mismatch', function () use ($hostPolicy): void {
            $policyXml = createPolicyXml($hostPolicy, 'required', null, 'does-not-match.example.invalid');
            $result = checkSignaturePolicy(TEST_HOSTS[0], $policyXml);
            if ($result['result'] === 'No connection') {
                throw new TestSkippedException($result['message']);
            }
            expectResult($result, 'Fail-Required');
        });
    }
} else {
    echo "SKIP: Fingerprint and SubjectConstraint mismatch cases require a successful example.com test\n";
}

echo "\n$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);

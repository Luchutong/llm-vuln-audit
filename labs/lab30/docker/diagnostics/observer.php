<?php
/**
 * Correlated diagnostics observer for controlled HTTP observations.
 *
 * This file is loaded through an optional php.ini prepend (compose.diagnostics.yaml),
 * never through the shop's business code.  It only records what PHP already produced:
 *
 * - it does not change the response body, status code, session or permissions;
 * - it returns false from the error handler, so PHP's own log/error handling still runs;
 * - it ignores every request without a runner-generated correlation id, which is the
 *   only way an operator can tell a controlled observation from ordinary traffic.
 *
 * The collected data is not proof that a vulnerability exists.  It is a server-side
 * observation attached to one request id.
 */

$__shop_diag_id = isset($_SERVER['HTTP_X_VERIFICATION_REQUEST_ID'])
    ? (string) $_SERVER['HTTP_X_VERIFICATION_REQUEST_ID'] : '';
if (!preg_match('/^[0-9a-f]{32}$/', $__shop_diag_id)) {
    return;
}

$__shop_diag_dir = getenv('SHOP_DIAGNOSTICS_DIR');
if (!is_string($__shop_diag_dir) || $__shop_diag_dir === '' || !is_dir($__shop_diag_dir)) {
    return;
}

$__shop_diag_errors = [];
$__shop_diag_relative = static function (string $file): string {
    foreach (['/var/www/shop/', '/var/www/'] as $prefix) {
        if (strncmp($file, $prefix, strlen($prefix)) === 0) {
            return substr($file, strlen($prefix));
        }
    }
    return basename($file);
};
$__shop_diag_record = static function (int $type, string $message, string $file, int $line) use (&$__shop_diag_errors, $__shop_diag_relative): void {
    if (count($__shop_diag_errors) >= 20) {
        return;
    }
    $kinds = [
        E_ERROR => 'php_fatal', E_PARSE => 'php_fatal', E_CORE_ERROR => 'php_fatal',
        E_COMPILE_ERROR => 'php_fatal', E_USER_ERROR => 'php_fatal', E_RECOVERABLE_ERROR => 'php_error',
        E_WARNING => 'php_warning', E_USER_WARNING => 'php_warning',
        E_NOTICE => 'php_notice', E_USER_NOTICE => 'php_notice', E_DEPRECATED => 'php_notice',
        E_USER_DEPRECATED => 'php_notice',
    ];
    $kind = $kinds[$type] ?? 'php_error';
    $text = preg_replace('/\s+/', ' ', (string) $message);
    $__shop_diag_errors[] = [
        'kind' => $kind,
        'message' => mb_substr((string) $text, 0, 500),
        'source_path' => $__shop_diag_relative((string) $file),
        'line' => (int) $line,
    ];
};

set_error_handler(static function (int $type, string $message, string $file = '', int $line = 0) use ($__shop_diag_record): bool {
    $__shop_diag_record($type, $message, $file, $line);
    return false; // let PHP's configured handler (log_errors) run unchanged
});

register_shutdown_function(static function () use ($__shop_diag_id, $__shop_diag_dir, &$__shop_diag_errors, $__shop_diag_record): void {
    $last = error_get_last();
    if (is_array($last) && !empty($last['message'])) {
        // The handler above may already have recorded this error; the shutdown list is
        // only meant to add the fatal errors PHP could not hand to it.
        $duplicate = false;
        foreach ($__shop_diag_errors as $seen) {
            if ($seen['line'] === (int) ($last['line'] ?? 0)
                && $seen['message'] === mb_substr((string) preg_replace('/\s+/', ' ', (string) $last['message']), 0, 500)) {
                $duplicate = true;
                break;
            }
        }
        if (!$duplicate) {
            $__shop_diag_record((int) ($last['type'] ?? E_ERROR), (string) $last['message'],
                (string) ($last['file'] ?? ''), (int) ($last['line'] ?? 0));
        }
    }
    $line = json_encode([
        'request_id' => $__shop_diag_id,
        'ts' => time(),
        'status' => http_response_code(),
        'request_uri' => substr((string) ($_SERVER['REQUEST_URI'] ?? ''), 0, 200),
        'errors' => $__shop_diag_errors,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (is_string($line)) {
        @file_put_contents(rtrim($__shop_diag_dir, '/') . '/diagnostics.jsonl', $line . "\n",
            FILE_APPEND | LOCK_EX);
    }
});

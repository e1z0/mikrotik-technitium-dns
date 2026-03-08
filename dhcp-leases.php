<?php
/**
 * dhcp-leases.php
 *
 * This script audits and optionally cleans DNS records that are automatically created from MikroTik DHCP leases. 
 * It compares the current DHCP lease tables from multiple MikroTik routers with DNS records stored in 
 * Technitium DNS Server and detects records that no longer correspond to active leases, 
 * as well as duplicate DNS records created for the same active lease.
 * The main goal is to remove stale or duplicate DNS entries that accumulate over time when DHCP lease 
 * expiration scripts fail to properly delete them.

 * The script supports two execution modes:
 * * Web UI mode – displays a clean HTML report showing routers, lease counts, stale records, duplicate records.
 * * CLI mode – outputs plain text lines suitable for terminal use, automation, or monitoring tools.
 *
 * PHP 5.6 compatible
 *
 * Requirements:
 * - Denis Basta RouterOS API class available as routeros_api.class.php
 * - cURL enabled
 *
 * Usage:
 *   php dhcp-leases.php
 *   php dhcp-leases.php --json
 *   php dhcp-leases.php --clean
 *   php dhcp-leases.php --clean --dryrun
 *   php dhcp-leases.php --clean --dryrun --json
 */
date_default_timezone_set('Europe/Vilnius');
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once __DIR__ . '/routeros_api.class.php';
$isCli = (php_sapi_name() === 'cli');

/* ============================================================
 * CONFIG
 * ============================================================ */


$config = array(
    'technitium' => array(
        'base_url' => 'https://technitium.domain.com',
        'token'    => 'TECHNITIUM_API_TOKEN',
        'domain'   => 'domain.com',
        'timeout'  => 20,
    ),
    'routers' => array(
    array(
        'name' => 'FW-LAB01',
        'host' => '192.168.1.1',
        'user' => 'testuser',
        'pass' => 'testpass',
        'port' => 8728,
        'domain'     => 'domain.com',
        'ptr_zone'   => '168.192.in-addr.arpa',
        'ptr_prefix' => '192.168', 
        'dns_tag'    => '#LAB01#DHCP2DNS#',
    ),
    array(
        'name' => 'FW-LAB02',
        'host' => '192.168.2.1',
        'user' => 'testuser',
        'pass' => 'testpass',
        'port' => 8728,
        'domain'     => 'domain.com',
        'ptr_zone'   => '168.192.in-addr.arpa',
        'ptr_prefix' => '192.168', 
        'dns_tag'    => '#LAB02#DHCP2DNS#',
    ),
    array(
        'name' => 'FW-LAB02',
        'host' => '192.168.3.1',
        'user' => 'testuser',
        'pass' => 'testpass',
        'port' => 8728,
        'domain'     => 'domain.com',
        'ptr_zone'   => '168.192.in-addr.arpa',
        'ptr_prefix' => '192.168', 
        'dns_tag'    => '#LAB03#DHCP2DNS#',
    ),
    ),
);

/* ============================================================
 * FLAGS
 * ============================================================ */

$flags = parseFlags(isset($argv) ? $argv : array());

/* ============================================================
 * MAIN
 * ============================================================ */

$result = runAudit($config, $flags);

if (!empty($flags['json'])) {
    if (!$isCli && !headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
    }
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit;
}

if ($isCli) {
    printCli($result, $flags);
    exit;
}

if (!headers_sent()) {
    header('Content-Type: text/html; charset=utf-8');
}
echo renderHtml($result, $flags);
exit;

/* ============================================================
 * CORE
 * ============================================================ */

function runAudit($config, $flags)
{
    $result = array(
        'success'         => true,
        'generated_at'    => date('c'),
        'mode'            => array(
            'json'   => !empty($flags['json']),
            'clean'  => !empty($flags['clean']),
            'dryrun' => !empty($flags['dryrun']),
        ),
        'technitium'      => array(
            'base_url' => $config['technitium']['base_url'],
            'domain'   => $config['technitium']['domain'],
        ),
        'summary'         => array(
            'routers_total'   => count($config['routers']),
            'routers_ok'      => 0,
            'routers_failed'  => 0,
            'lease_ips_total' => 0,

            'invalid_total'   => 0,
            'invalid_a'       => 0,
            'invalid_ptr'     => 0,

            'duplicate_total' => 0,
            'duplicate_a'     => 0,
            'duplicate_ptr'   => 0,

            'deleted'         => 0,
            'would_delete'    => 0,
            'delete_failed'   => 0,
        ),
        'errors'          => array(),
        'routers'         => array(),
        'invalid_records' => array(),
    );

    $forwardZone = $config['technitium']['domain'];

    foreach ($config['routers'] as $router) {
        $routerReport = array(
            'router'          => $router['name'],
            'host'            => $router['host'],
            'ptr_zone'        => $router['ptr_zone'],
            'ptr_prefix'      => $router['ptr_prefix'],
            'dns_tag'         => $router['dns_tag'],
            'lease_ips_count' => 0,
            'status'          => 'ok',
            'errors'          => array(),
        );

        $leaseIps = getMikroTikLeaseIps($router, $routerReport['errors']);
        if ($leaseIps === false) {
            $routerReport['status'] = 'router_connect_failed';
            $result['summary']['routers_failed']++;
            $result['errors'][] = 'Failed to pull DHCP leases from ' . $router['name'] . ' (' . $router['host'] . ')';
            $result['routers'][] = $routerReport;
            continue;
        }

        $result['summary']['routers_ok']++;
        $routerReport['lease_ips_count'] = count($leaseIps);
        $result['summary']['lease_ips_total'] += count($leaseIps);

        $forwardRecordsResponse = technitiumGetZoneRecords($config['technitium'], $forwardZone);
        if ($forwardRecordsResponse['ok']) {
            $forwardRecords = normalizeTechnitiumRecords($forwardRecordsResponse['records'], $forwardZone);
        } else {
            $forwardRecords = array();
            $routerReport['errors'][] = 'Forward zone read failed: ' . $forwardRecordsResponse['error'];
            $result['errors'][] = 'Forward zone read failed for ' . $router['name'] . ': ' . $forwardRecordsResponse['error'];
            $result['success'] = false;
        }

        $ptrRecordsResponse = technitiumGetZoneRecords($config['technitium'], $router['ptr_zone']);
        if ($ptrRecordsResponse['ok']) {
            $ptrRecords = normalizeTechnitiumRecords($ptrRecordsResponse['records'], $router['ptr_zone']);
        } else {
            $ptrRecords = array();
            $routerReport['errors'][] = 'PTR zone read failed: ' . $ptrRecordsResponse['error'];
            $result['errors'][] = 'PTR zone read failed for ' . $router['name'] . ': ' . $ptrRecordsResponse['error'];
            $result['success'] = false;
        }

        $invalidForward   = findInvalidForwardRecords($router, $forwardZone, $forwardRecords, $leaseIps);
        $invalidPtr       = findInvalidPtrRecords($router, $ptrRecords, $leaseIps);
        $duplicateForward = findDuplicateForwardRecords($router, $forwardZone, $forwardRecords, $leaseIps);
        $duplicatePtr     = findDuplicatePtrRecords($router, $ptrRecords, $leaseIps);

        $recordsToProcess = array_merge(
            $invalidForward,
            $invalidPtr,
            $duplicateForward,
            $duplicatePtr
        );

        if (!empty($flags['clean'])) {
            $recordsToProcess = processCleanup($config['technitium'], $recordsToProcess, $flags);
        } else {
            $recordsToProcess = markNoCleanup($recordsToProcess);
        }

        foreach ($recordsToProcess as $item) {
            $result['invalid_records'][] = $item;

            if (isset($item['category']) && $item['category'] === 'duplicate') {
                $result['summary']['duplicate_total']++;

                if ($item['type'] === 'A') {
                    $result['summary']['duplicate_a']++;
                } elseif ($item['type'] === 'PTR') {
                    $result['summary']['duplicate_ptr']++;
                }
            } else {
                $result['summary']['invalid_total']++;

                if ($item['type'] === 'A') {
                    $result['summary']['invalid_a']++;
                } elseif ($item['type'] === 'PTR') {
                    $result['summary']['invalid_ptr']++;
                }
            }

            if ($item['action'] === 'deleted') {
                $result['summary']['deleted']++;
            } elseif ($item['action'] === 'would_delete') {
                $result['summary']['would_delete']++;
            } elseif ($item['action'] === 'delete_failed') {
                $result['summary']['delete_failed']++;
                $result['success'] = false;
            }
        }

        $result['routers'][] = $routerReport;
    }

    return $result;
}

/* ============================================================
 * MIKROTIK
 * ============================================================ */

function getMikroTikLeaseIps($router, &$errors)
{
    $API = new RouterosAPI();
    $API->debug = false;

    $port = isset($router['port']) ? (int)$router['port'] : 8728;
    $ok = @$API->connect($router['host'], $router['user'], $router['pass'], $port);

    if (!$ok) {
        $errors[] = 'Unable to connect to MikroTik API';
        return false;
    }

    $leases = @$API->comm('/ip/dhcp-server/lease/print');
    @$API->disconnect();

    if (!is_array($leases)) {
        $errors[] = 'Lease list is not an array';
        return false;
    }

    $ips = array();

    foreach ($leases as $lease) {
        if (!is_array($lease)) {
            continue;
        }

        $disabled = getArrayValue($lease, 'disabled', '');
        if (isTruthy($disabled)) {
            continue;
        }

        $status = strtolower(trim((string)getArrayValue($lease, 'status', '')));
        if ($status !== '' && $status !== 'bound') {
            continue;
        }

        $ip = trim((string)getArrayValue($lease, 'address', ''));
        if ($ip === '' || !isValidIpv4($ip)) {
            continue;
        }

        $ips[$ip] = true;
    }

    return $ips;
}

/* ============================================================
 * TECHNITIUM API
 * ============================================================ */

function technitiumGetZoneRecords($technitium, $zone)
{
    $params = array(
        'token'    => $technitium['token'],
        'domain'   => $zone,
        'zone'     => $zone,
        'listZone' => 'true',
    );

    $res = technitiumApiCall($technitium, '/api/zones/records/get', $params, 'GET');
    if (!$res['ok']) {
        return $res;
    }

    $records = array();

    if (isset($res['data']['response']['records']) && is_array($res['data']['response']['records'])) {
        $records = $res['data']['response']['records'];
    } elseif (isset($res['data']['records']) && is_array($res['data']['records'])) {
        $records = $res['data']['records'];
    } elseif (isset($res['data']['response']) && is_array($res['data']['response'])) {
        $records = $res['data']['response'];
    }

    return array(
        'ok'      => true,
        'records' => $records,
        'error'   => '',
        'raw'     => $res['data'],
    );
}

function technitiumDeleteRecord($technitium, $zone, $record)
{
    $domain = buildRecordFqdn($record['name'], $zone);

    $params = array(
        'token'  => $technitium['token'],
        'zone'   => $zone,
        'domain' => $domain,
        'type'   => $record['type'],
        'value'  => $record['value'],
    );

    if ($record['type'] === 'A' || $record['type'] === 'AAAA') {
        $params['ipAddress'] = $record['value'];
    } elseif ($record['type'] === 'PTR') {
        $params['ptrName'] = $record['value'];
    }

    return technitiumApiCall($technitium, '/api/zones/records/delete', $params, 'GET');
}

function technitiumApiCall($technitium, $path, $params, $method)
{
    $baseUrl = rtrim($technitium['base_url'], '/');
    $url = $baseUrl . $path;

    $ch = curl_init();

    if (strtoupper($method) === 'GET') {
        $url .= '?' . http_build_query($params);
    }

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, isset($technitium['timeout']) ? (int)$technitium['timeout'] : 20);
    curl_setopt($ch, CURLOPT_TIMEOUT, isset($technitium['timeout']) ? (int)$technitium['timeout'] : 20);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    if (strtoupper($method) === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/x-www-form-urlencoded'
        ));
    }

    $body = curl_exec($ch);
    $errno = curl_errno($ch);
    $error = curl_error($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($errno) {
        return array(
            'ok'    => false,
            'error' => 'cURL error: ' . $error,
            'data'  => null,
        );
    }

    if ($httpCode < 200 || $httpCode >= 300) {
        return array(
            'ok'    => false,
            'error' => 'HTTP ' . $httpCode . ': ' . $body,
            'data'  => null,
        );
    }

    $json = json_decode($body, true);
    if (!is_array($json)) {
        return array(
            'ok'    => false,
            'error' => 'Invalid JSON response: ' . $body,
            'data'  => null,
        );
    }

    if (isset($json['status']) && $json['status'] !== 'ok') {
        $msg = getArrayValue($json, 'errorMessage', 'API returned status=' . $json['status']);
        return array(
            'ok'    => false,
            'error' => $msg,
            'data'  => $json,
        );
    }

    return array(
        'ok'    => true,
        'error' => '',
        'data'  => $json,
    );
}

/* ============================================================
 * RECORD NORMALIZATION
 * ============================================================ */

function normalizeTechnitiumRecords($records, $zone)
{
    $out = array();

    foreach ($records as $record) {
        if (!is_array($record)) {
            continue;
        }

        $type = strtoupper(trim((string)getArrayValue($record, 'type', '')));
        if ($type === '') {
            continue;
        }

        $name = normalizeRecordName(getArrayValue($record, 'name', ''), $zone);
        $disabled = isTruthy(getArrayValue($record, 'disabled', false));
        $comments = trim((string)getArrayValue($record, 'comments', ''));

        $value = extractRecordValue($record, $type);

        $out[] = array(
            'name'     => $name,
            'type'     => $type,
            'value'    => $value,
            'comments' => $comments,
            'disabled' => $disabled,
            'raw'      => $record,
        );
    }

    return $out;
}

function extractRecordValue($record, $type)
{
    $rData = array();
    if (isset($record['rData']) && is_array($record['rData'])) {
        $rData = $record['rData'];
    } elseif (isset($record['rdata']) && is_array($record['rdata'])) {
        $rData = $record['rdata'];
    }

    switch ($type) {
        case 'A':
        case 'AAAA':
            return trim((string)getArrayValue($rData, 'ipAddress', getArrayValue($record, 'value', '')));

        case 'PTR':
            return trim((string)getArrayValue($rData, 'ptrName', getArrayValue($record, 'value', '')));

        default:
            return trim((string)getArrayValue($record, 'value', ''));
    }
}

/* ============================================================
 * INVALID DETECTION
 * ============================================================ */

function findDuplicateForwardRecords($router, $zone, $records, $leaseIps)
{
    $byIp = array();
    $duplicates = array();

    foreach ($records as $record) {
        if ($record['disabled']) {
            continue;
        }

        if ($record['type'] !== 'A') {
            continue;
        }

        if (!commentMatchesTag($record['comments'], $router['dns_tag'])) {
            continue;
        }

        $ip = trim($record['value']);
        if ($ip === '' || !isValidIpv4($ip)) {
            continue;
        }

        if (!isset($leaseIps[$ip])) {
            continue;
        }

        if (!isset($byIp[$ip])) {
            $byIp[$ip] = array();
        }

        $byIp[$ip][] = $record;
    }

    foreach ($byIp as $ip => $items) {
        if (count($items) <= 1) {
            continue;
        }

        $keepIndex = chooseBestForwardRecordIndex($items);

        foreach ($items as $idx => $record) {
            if ($idx == $keepIndex) {
                continue;
            }

            $row = buildInvalidRecordRow(
                $router,
                $zone,
                $record,
                $ip,
                'Duplicate tagged A record for active DHCP IP'
            );
            $row['category'] = 'duplicate';
            $duplicates[] = $row;
        }
    }

    return $duplicates;
}

function chooseBestForwardRecordIndex($items)
{
    $bestIdx = 0;
    $bestScore = -1;

    foreach ($items as $idx => $record) {
        $score = 0;
        $name = trim((string)$record['name']);

        if ($name !== '' && $name !== '@') {
            $score += 10;
            $score += max(0, 20 - strlen($name));
        }

        if (trim((string)$record['value']) !== '') {
            $score += 3;
        }

        if ($score > $bestScore) {
            $bestScore = $score;
            $bestIdx = $idx;
        }
    }

    return $bestIdx;
}

function findDuplicatePtrRecords($router, $records, $leaseIps)
{
    $byIp = array();
    $duplicates = array();

    foreach ($records as $record) {
        if ($record['disabled']) {
            continue;
        }

        if ($record['type'] !== 'PTR') {
            continue;
        }

        if (!commentMatchesTag($record['comments'], $router['dns_tag'])) {
            continue;
        }

        $resolvedIp = ptrRecordToIpv4ByPrefix($record['name'], $router['ptr_prefix']);
        if ($resolvedIp === '') {
            continue;
        }

        if (!isset($leaseIps[$resolvedIp])) {
            continue;
        }

        if (!isset($byIp[$resolvedIp])) {
            $byIp[$resolvedIp] = array();
        }

        $byIp[$resolvedIp][] = $record;
    }

    foreach ($byIp as $ip => $items) {
        if (count($items) <= 1) {
            continue;
        }

        $keepIndex = chooseBestPtrRecordIndex($items);

        foreach ($items as $idx => $record) {
            if ($idx == $keepIndex) {
                continue;
            }

            $row = buildInvalidRecordRow(
                $router,
                $router['ptr_zone'],
                $record,
                $ip,
                'Duplicate tagged PTR record for active DHCP IP'
            );
            $row['category'] = 'duplicate';
            $duplicates[] = $row;
        }
    }

    return $duplicates;
}

function chooseBestPtrRecordIndex($items)
{
    $bestIdx = 0;
    $bestScore = -1;

    foreach ($items as $idx => $record) {
        $score = 0;
        $value = trim((string)$record['value']);
        $name  = trim((string)$record['name']);

        if ($value !== '') {
            $score += 10;
        }

        if ($name !== '' && $name !== '@') {
            $score += 5;
        }

        if ($score > $bestScore) {
            $bestScore = $score;
            $bestIdx = $idx;
        }
    }

    return $bestIdx;
}

function findInvalidForwardRecords($router, $zone, $records, $leaseIps)
{
    $invalid = array();

    foreach ($records as $record) {
        if ($record['disabled']) {
            continue;
        }

        if ($record['type'] !== 'A') {
            continue;
        }

        if (!commentMatchesTag($record['comments'], $router['dns_tag'])) {
            continue;
        }

        $ip = trim($record['value']);
        if ($ip === '' || !isValidIpv4($ip)) {
            $invalid[] = buildInvalidRecordRow(
                $router,
                $zone,
                $record,
                '',
                'Forward A record has invalid or empty IP'
            );
            continue;
        }

        if (!isset($leaseIps[$ip])) {
            $invalid[] = buildInvalidRecordRow(
                $router,
                $zone,
                $record,
                $ip,
                'IP not found in current DHCP leases of this router'
            );
        }
    }

    return $invalid;
}

function findInvalidPtrRecords($router, $records, $leaseIps)
{
    $invalid = array();

    foreach ($records as $record) {
        if ($record['disabled']) {
            continue;
        }

        if ($record['type'] !== 'PTR') {
            continue;
        }

        if (!commentMatchesTag($record['comments'], $router['dns_tag'])) {
            continue;
        }

        $resolvedIp = ptrRecordToIpv4ByPrefix($record['name'], $router['ptr_prefix']);

        if ($resolvedIp === '') {
            $invalid[] = buildInvalidRecordRow(
                $router,
                $router['ptr_zone'],
                $record,
                '',
                'Unable to reconstruct IPv4 from PTR name using ptr_prefix=' . $router['ptr_prefix']
            );
            continue;
        }

        if (!isset($leaseIps[$resolvedIp])) {
            $invalid[] = buildInvalidRecordRow(
                $router,
                $router['ptr_zone'],
                $record,
                $resolvedIp,
                'IP not found in current DHCP leases of this router'
            );
        }
    }

    return $invalid;
}

function buildInvalidRecordRow($router, $zone, $record, $resolvedIp, $reason)
{
    return array(
        'router'       => $router['name'],
        'router_host'  => $router['host'],
        'zone'         => $zone,
        'type'         => $record['type'],
        'name'         => $record['name'],
        'fqdn'         => buildRecordFqdn($record['name'], $zone),
        'value'        => $record['value'],
        'resolved_ip'  => $resolvedIp,
        'comment'      => $record['comments'],
        'reason'       => $reason,
        'category'     => 'invalid',
        'action'       => 'none',
        'delete_ok'    => null,
        'delete_error' => '',
        'record'       => $record,
    );
}

/* ============================================================
 * CLEANUP
 * ============================================================ */

function processCleanup($technitium, $invalid, $flags)
{
    $out = array();

    foreach ($invalid as $row) {
        if (!empty($flags['dryrun'])) {
            $row['action'] = 'would_delete';
            $row['delete_ok'] = true;
            $out[] = $row;
            continue;
        }

        $delete = technitiumDeleteRecord($technitium, $row['zone'], $row['record']);
        if ($delete['ok']) {
            $row['action'] = 'deleted';
            $row['delete_ok'] = true;
        } else {
            $row['action'] = 'delete_failed';
            $row['delete_ok'] = false;
            $row['delete_error'] = $delete['error'];
        }

        $out[] = $row;
    }

    return $out;
}

function markNoCleanup($invalid)
{
    $out = array();

    foreach ($invalid as $row) {
        $row['action'] = 'report_only';
        $out[] = $row;
    }

    return $out;
}

/* ============================================================
 * HELPERS
 * ============================================================ */

function parseFlags($argv)
{
    $flags = array(
        'json'   => false,
        'clean'  => false,
        'dryrun' => false,
    );

    if (!is_array($argv)) {
        return $flags;
    }

    foreach ($argv as $arg) {
        if ($arg === '--json') {
            $flags['json'] = true;
        } elseif ($arg === '--clean') {
            $flags['clean'] = true;
        } elseif ($arg === '--dryrun') {
            $flags['dryrun'] = true;
        }
    }

    return $flags;
}

function getArrayValue($array, $key, $default)
{
    return isset($array[$key]) ? $array[$key] : $default;
}

function isTruthy($value)
{
    if (is_bool($value)) {
        return $value;
    }

    $value = strtolower(trim((string)$value));
    return in_array($value, array('1', 'true', 'yes', 'on'), true);
}

function isValidIpv4($ip)
{
    return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
}

function normalizeRecordName($name, $zone)
{
    $name = trim((string)$name);
    $zone = trim((string)$zone);

    if ($name === '' || $name === '@') {
        return '@';
    }

    $name = rtrim($name, '.');
    $zone = rtrim($zone, '.');

    if ($name === $zone) {
        return '@';
    }

    $suffix = '.' . $zone;
    if (substr($name, -strlen($suffix)) === $suffix) {
        $name = substr($name, 0, -strlen($suffix));
    }

    return $name === '' ? '@' : $name;
}

function buildRecordFqdn($name, $zone)
{
    $name = trim((string)$name);
    $zone = rtrim(trim((string)$zone), '.');

    if ($name === '' || $name === '@') {
        return $zone;
    }

    $name = rtrim($name, '.');

    if (substr($name, -strlen('.' . $zone)) === '.' . $zone || $name === $zone) {
        return $name;
    }

    return $name . '.' . $zone;
}

function commentMatchesTag($comment, $tag)
{
    if ($tag === '') {
        return false;
    }

    return strpos((string)$comment, (string)$tag) !== false;
}

/**
 * Rebuild IPv4 from PTR record name using explicit router prefix.
 *
 * Examples with ptr_prefix=10.1:
 *   name=55       -> 10.1.0.55
 *   name=0.55     -> 10.1.0.55
 *   name=12.55    -> 10.1.12.55
 *
 * Examples with ptr_prefix=10.20:
 *   name=33       -> 10.20.0.33
 *   name=4.33     -> 10.20.4.33
 *
 * This matches your non-standard reverse zone design much better.
 */
function ptrRecordToIpv4ByPrefix($name, $ptrPrefix)
{
    $name = trim((string)$name);
    $ptrPrefix = trim((string)$ptrPrefix);

    if ($name === '' || $name === '@' || $ptrPrefix === '') {
        return '';
    }

    $prefixParts = explode('.', $ptrPrefix);
    if (count($prefixParts) !== 2) {
        return '';
    }

    if (!isOctet($prefixParts[0]) || !isOctet($prefixParts[1])) {
        return '';
    }

    $name = trim($name, '.');
    $nameParts = explode('.', $name);

    foreach ($nameParts as $p) {
        if (!isOctet($p)) {
            return '';
        }
    }

    if (count($nameParts) === 1) {
        // 228 -> 10.2.0.228
        return $prefixParts[0] . '.' . $prefixParts[1] . '.0.' . $nameParts[0];
    }

    if (count($nameParts) === 2) {
        // 228.11 -> 10.2.11.228
        return $prefixParts[0] . '.' . $prefixParts[1] . '.' . $nameParts[1] . '.' . $nameParts[0];
    }

    return '';
}

function isOctet($v)
{
    if (!ctype_digit((string)$v)) {
        return false;
    }
    $n = (int)$v;
    return $n >= 0 && $n <= 255;
}

/* ============================================================
 * OUTPUT
 * ============================================================ */

function printCli($result, $flags)
{
    echo "DHCP DNS cleanup report\n";
    echo "Generated: " . $result['generated_at'] . "\n\n";

    echo "Routers OK: " . $result['summary']['routers_ok'] . "/" . $result['summary']['routers_total'] . "\n";
    echo "Lease IPs:  " . $result['summary']['lease_ips_total'] . "\n";
    echo "Invalid A:  " . $result['summary']['invalid_a'] . "\n";
    echo "Invalid PTR:" . $result['summary']['invalid_ptr'] . "\n";
    echo "Total invalid: " . $result['summary']['invalid_total'] . "\n\n";

    if (!empty($result['errors'])) {
        echo "Errors:\n";
        foreach ($result['errors'] as $e) {
            echo "  - $e\n";
        }
        echo "\n";
    }

    if (empty($result['invalid_records'])) {
        echo "No invalid DNS records found.\n";
        return;
    }

    foreach ($result['invalid_records'] as $r) {
        $line = array(
            $r['router'],
            $r['zone'],
            $r['type'],
            $r['fqdn'],
            $r['value'],
            $r['resolved_ip'],
            $r['action'],
            $r['reason']
        );

        echo implode(" | ", $line) . "\n";
    }

    echo "\n";

    if (!empty($flags['clean'])) {
        if (!empty($flags['dryrun'])) {
            echo "Mode: CLEAN DRYRUN (no records deleted)\n";
        } else {
            echo "Deleted: " . $result['summary']['deleted'] . "\n";
            echo "Delete failed: " . $result['summary']['delete_failed'] . "\n";
        }
    }
}



function renderHtml($result, $flags)
{
    $html = '';
    $html .= '<!DOCTYPE html><html><head><meta charset="utf-8">';
    $html .= '<title>DHCP DNS Cleanup Report</title>';
    $html .= '<style type="text/css">';
    $html .= 'body{font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222;background:#f5f7fa;margin:20px;}';
    $html .= 'h1,h2{margin:0 0 12px 0;}';
    $html .= '.meta,.box{background:#fff;border:1px solid #d8dee6;border-radius:8px;padding:14px;margin:0 0 16px 0;}';
    $html .= '.summary{display:inline-block;margin-right:30px;vertical-align:top;}';
    $html .= '.summary b{display:block;font-size:20px;margin-bottom:4px;}';
    $html .= 'table{border-collapse:collapse;width:100%;background:#fff;}';
    $html .= 'th,td{border:1px solid #d8dee6;padding:8px 10px;text-align:left;vertical-align:top;}';
    $html .= 'th{background:#eef3f8;}';
    $html .= 'tr:nth-child(even) td{background:#fafcff;}';
    $html .= '.tag{display:inline-block;padding:3px 8px;border-radius:12px;font-size:12px;font-weight:bold;background:#eef3f8;border:1px solid #d8dee6;margin-right:6px;}';
    $html .= '.bad{background:#ffe9e9;border-color:#f0b6b6;color:#a10000;}';
    $html .= '.warn{background:#fff4df;border-color:#f0d39a;color:#7a5300;}';
    $html .= '.ok{background:#e9f9ee;border-color:#b6e1c0;color:#0d6b2f;}';
    $html .= '.small{font-size:12px;}';
    $html .= '</style></head><body>';

    $html .= '<h1>DHCP → DNS stale record report</h1>';

    $html .= '<div class="meta">';
    $html .= '<div class="summary"><b>' . (int)$result['summary']['invalid_total'] . '</b>Invalid records</div>';
    $html .= '<div class="summary"><b>' . (int)$result['summary']['invalid_a'] . '</b>Invalid A</div>';
    $html .= '<div class="summary"><b>' . (int)$result['summary']['invalid_ptr'] . '</b>Invalid PTR</div>';
    $html .= '<div class="summary"><b>' . (int)$result['summary']['lease_ips_total'] . '</b>Lease IPs</div>';
    $html .= '<div class="summary"><b>' . (int)$result['summary']['routers_ok'] . '/' . (int)$result['summary']['routers_total'] . '</b>Routers OK</div>';
    $html .= '<div style="margin-top:14px;">';

    if (!empty($flags['clean']) && !empty($flags['dryrun'])) {
        $html .= '<span class="tag warn">Mode: CLEAN + DRYRUN</span>';
    } elseif (!empty($flags['clean'])) {
        $html .= '<span class="tag bad">Mode: CLEAN</span>';
    } else {
        $html .= '<span class="tag">Mode: REPORT ONLY</span>';
    }

    $html .= '<span class="tag">Domain: ' . h($result['technitium']['domain']) . '</span>';
    $html .= '</div></div>';

    if (!empty($result['errors'])) {
        $html .= '<div class="box"><h2>Errors</h2><ul>';
        foreach ($result['errors'] as $error) {
            $html .= '<li>' . h($error) . '</li>';
        }
        $html .= '</ul></div>';
    }

    $html .= '<div class="box"><h2>Routers</h2><table>';
    $html .= '<tr><th>Router</th><th>Host</th><th>PTR Zone</th><th>PTR Prefix</th><th>Tag</th><th>Lease IPs</th><th>Status</th><th>Errors</th></tr>';

    foreach ($result['routers'] as $router) {
        $statusClass = $router['status'] === 'ok' ? 'ok' : 'bad';
        $html .= '<tr>';
        $html .= '<td>' . h($router['router']) . '</td>';
        $html .= '<td>' . h($router['host']) . '</td>';
        $html .= '<td>' . h($router['ptr_zone']) . '</td>';
        $html .= '<td>' . h($router['ptr_prefix']) . '</td>';
        $html .= '<td>' . h($router['dns_tag']) . '</td>';
        $html .= '<td>' . (int)$router['lease_ips_count'] . '</td>';
        $html .= '<td><span class="tag ' . $statusClass . '">' . h($router['status']) . '</span></td>';
        $html .= '<td class="small">' . h(implode(' | ', $router['errors'])) . '</td>';
        $html .= '</tr>';
    }

    $html .= '</table></div>';

    $html .= '<div class="box"><h2>Invalid DNS records</h2>';

    if (empty($result['invalid_records'])) {
        $html .= '<div class="tag ok">No invalid records found</div>';
    } else {
        $html .= '<table>';
        $html .= '<tr><th>#</th><th>Router</th><th>Zone</th><th>Type</th><th>Name</th><th>FQDN</th><th>Value</th><th>Resolved IP</th><th>Comment</th><th>Reason</th><th>Action</th></tr>';

        $i = 1;
        foreach ($result['invalid_records'] as $row) {
            $actionClass = 'warn';
            if ($row['action'] === 'deleted') {
                $actionClass = 'ok';
            } elseif ($row['action'] === 'delete_failed') {
                $actionClass = 'bad';
            }

            $actionText = $row['action'];
            if ($row['delete_error'] !== '') {
                $actionText .= ' - ' . $row['delete_error'];
            }

            $html .= '<tr>';
            $html .= '<td>' . $i . '</td>';
            $html .= '<td>' . h($row['router']) . '</td>';
            $html .= '<td>' . h($row['zone']) . '</td>';
            $html .= '<td>' . h($row['type']) . '</td>';
            $html .= '<td>' . h($row['name']) . '</td>';
            $html .= '<td>' . h($row['fqdn']) . '</td>';
            $html .= '<td>' . h($row['value']) . '</td>';
            $html .= '<td>' . h($row['resolved_ip']) . '</td>';
            $html .= '<td>' . h($row['comment']) . '</td>';
            $html .= '<td>' . h($row['reason']) . '</td>';
            $html .= '<td><span class="tag ' . $actionClass . '">' . h($actionText) . '</span></td>';
            $html .= '</tr>';
            $i++;
        }

        $html .= '</table>';
    }

    $html .= '</div></body></html>';

    return $html;
}

function h($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

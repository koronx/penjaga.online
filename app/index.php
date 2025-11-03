<?php
require __DIR__ . '/vendor/autoload.php';

use Workerman\Worker;
use Workerman\Coroutine;

// Jalankan di port 8053 (tidak perlu root)
$udpWorker = new Worker("udp://0.0.0.0:8053");

// Statistik global
$stats = [
    'total'    => 0,
    'cache'    => 0,
    'upstream' => 0,
    'local'    => 0,
];

$recentQueries = [];

$udpWorker->name = 'PHP-DNS-Hybrid-CacheTTL';
$udpWorker->count = 4;

// Folder cache
define('CACHE_DIR', __DIR__ . '/dns-cache');

// Forwarder DNS
const UPSTREAM_DNS = '8.8.8.8';
const UPSTREAM_PORT = 53;

// Record lokal (manual zone)
$records = [
    'router.lan' => [
        'A' => ['192.168.1.1'],
    ],
    'example.test' => [
        'A' => ['203.0.113.20'],
        'MX' => [['priority' => 10, 'host' => 'mail.example.test']],
        'TXT' => ['"v=spf1 include:_spf.example.test ~all"'],
        'CNAME' => ['alias.example.net'],
    ],
];
// --- Helper Functions ---

function saveToCacheAsync($domain, $qtype, $response)
{
    Coroutine::create(function () use ($domain, $qtype, $response) {
        if (!is_dir(CACHE_DIR)) {
            mkdir(CACHE_DIR, 0777, true);
        }
        $ttl = extractTTL($response);
        $data = [
            'expires' => time() + $ttl,
            'ttl' => $ttl,
            'data' => base64_encode($response)
        ];
        file_put_contents(getCachePath($domain.'/'.$qtype), json_encode($data));        
        // echo "  💾 Cached $domain (TTL={$ttl}s) via Coroutine\n";
    });
}
function encodeDomain($domain)
{
    $parts = explode('.', $domain);
    $encoded = '';
    foreach ($parts as $p) {
        $encoded .= chr(strlen($p)) . $p;
    }
    return $encoded . "\x00";
}

function parseDomain($data, &$offset)
{
    $labels = [];
    $len = ord($data[$offset++]);
    while ($len > 0) {
        $labels[] = substr($data, $offset, $len);
        $offset += $len;
        $len = ord($data[$offset++]);
    }
    return implode('.', $labels);
}

function buildResponse($query, $domain, $records, $qtype = 1)
{
    $transactionId = substr($query, 0, 2);
    $flags = "\x81\x80";
    $qdcount = substr($query, 4, 2);
    $ancount = "\x00\x00"; // nanti dihitung
    $nscount = "\x00\x00";
    $arcount = "\x00\x00";

    $offset = 12;
    parseDomain($query, $offset);
    $question = substr($query, 12, $offset - 12 + 4);

    // Map tipe numerik ke teks
    $typeMap = [
        1 => 'A',
        28 => 'AAAA',
        15 => 'MX',
        5 => 'CNAME',
        16 => 'TXT',
    ];

    $typeName = $typeMap[$qtype] ?? null;
    if (!$typeName || !isset($records[$domain][$typeName])) {
        return false; // tidak ada record
    }

    $answers = '';
    foreach ($records[$domain][$typeName] as $record) {
        $answers .= "\xc0\x0c"; // pointer ke nama
        switch ($typeName) {
            case 'A':
                $answers .= "\x00\x01\x00\x01"; // Type A, Class IN
                $answers .= "\x00\x00\x00\x3c"; // TTL
                $answers .= "\x00\x04";
                $answers .= implode('', array_map('chr', explode('.', $record)));
                break;

            case 'AAAA':
                $answers .= "\x00\x1c\x00\x01"; // Type AAAA
                $answers .= "\x00\x00\x00\x3c";
                $answers .= "\x00\x10";
                $answers .= inet_pton($record);
                break;

            case 'CNAME':
                $answers .= "\x00\x05\x00\x01"; // Type CNAME
                $answers .= "\x00\x00\x00\x3c";
                $encoded = encodeDomain($record);
                $answers .= pack('n', strlen($encoded)) . $encoded;
                break;

            case 'TXT':
                $answers .= "\x00\x10\x00\x01"; // Type TXT
                $answers .= "\x00\x00\x00\x3c";
                $txt = $record;
                $answers .= pack('n', strlen($txt) + 1);
                $answers .= chr(strlen($txt)) . $txt;
                break;

            case 'MX':
                $answers .= "\x00\x0f\x00\x01"; // Type MX
                $answers .= "\x00\x00\x00\x3c";
                $encoded = encodeDomain($record['host']);
                $rdata = pack('n', $record['priority']) . $encoded;
                $answers .= pack('n', strlen($rdata)) . $rdata;
                break;
        }
    }

    $ancount = pack('n', count($records[$domain][$typeName]));
    $header = $transactionId . $flags . $qdcount . $ancount . $nscount . $arcount;

    return $header . $question . $answers;
}

// --- Cache Functions ---

function getCachePath($domain)
{
    $cache_path = CACHE_DIR . '/' . md5(strtolower($domain)) . '.json';
    // echo "Cache path for $domain: $cache_path\n";
    return $cache_path;
}

function loadFromCache($domain, $qtype)
{
    $path = getCachePath($domain.'/'.$qtype);
    if (!file_exists($path)) return false;
    $data = json_decode(file_get_contents($path), true);
    if (!$data || time() > $data['expires']) {
        @unlink($path);
        return false;
    }
    return base64_decode($data['data']);
}

// --- Parse TTL dari paket DNS (ambil TTL pertama) ---
function extractTTL($response)
{
    // Minimal panjang header DNS = 12 byte
    if (strlen($response) < 12) return 60;

    // Ambil jumlah pertanyaan & jawaban
    $qdcount = unpack('n', substr($response, 4, 2))[1] ?? 0;
    $ancount = unpack('n', substr($response, 6, 2))[1] ?? 0;
    $offset = 12;

    // Skip semua pertanyaan (QNAME + QTYPE + QCLASS)
    for ($i = 0; $i < $qdcount; $i++) {
        while ($offset < strlen($response) && ord($response[$offset]) != 0) {
            $offset += ord($response[$offset]) + 1;
        }
        $offset += 5; // 1 byte null + 4 byte QTYPE/QCLASS
    }

    // Jika tidak ada jawaban, default TTL 60
    if ($ancount === 0) return 60;

    // Pastikan cukup panjang untuk baca jawaban
    if ($offset + 10 > strlen($response)) return 60;

    // Lewati pointer NAME (biasanya 2 byte 0xC0 0x0C)
    $offset += 2; // pointer ke QNAME

    // Pastikan masih cukup panjang
    if ($offset + 8 > strlen($response)) return 60;

    // Baca TYPE(2) + CLASS(2) + TTL(4)
    $offset += 4; // lompat TYPE + CLASS
    $ttlData = substr($response, $offset, 4);
    if (strlen($ttlData) < 4) return 60;

    $ttl = unpack('N', $ttlData)[1] ?? 60;
    return max(30, min($ttl, 86400)); // TTL aman (min 30s, max 1d)
}

function printStats($stats)
{
    // echo "📊 Stats — Total: {$stats['total']} | Cache Hit: {$stats['cache']} | Upstream: {$stats['upstream']} | Local: {$stats['local']}\n";
}

function saveStats($stats, $recentQueries)
{
    Coroutine::create(function () use ($stats, $recentQueries) {
        $data = [
            'timestamp' => date('c'),
            'stats' => $stats,
            'recent_queries' => array_slice($recentQueries, -10)
        ];
        file_put_contents(__DIR__ . '/dns-stats.json', json_encode($data));
        // echo "📊 Stats saved\n";
    });    
}

function loadStats()
{
    $file = __DIR__ . '/dns-stats.json';
    if (!file_exists($file)) {
        return [
            'timestamp' => date('c'),
            'stats' => ['total' => 0, 'cache' => 0, 'upstream' => 0, 'local' => 0],
            'recent_queries' => []
        ];
    }
    return json_decode(file_get_contents($file), true);
}

// --- Main Handler ---

$udpWorker->onMessage = function ($connection, $data) use ($records, &$stats, &$recentQueries) {    
    $offset = 12;
    $domain = parseDomain($data, $offset);
    $qtype = unpack('n', substr($data, $offset, 2))[1];
    $qclass = unpack('n', substr($data, $offset + 2, 2))[1];
    $stats['total']++;

    $origin_ip = $connection->getRemoteIp();

    $recentQueries[] = "$domain/" . $qtype;
    if (count($recentQueries) > 10) array_shift($recentQueries);

    // echo "DNS Query From: $origin_ip $domain (QTYPE=$qtype)\n";
    
    // === LOCAL RECORD ===
    if (isset($records[$domain])) {
        $response = buildResponse($data, $domain, $records, $qtype);
        if ($response) {
            $connection->send($response);
            $stats['local']++;
            // echo "  → Reply (local, type=$qtype)\n";
            saveStats($stats, $recentQueries);
            // printStats($stats);
            return;
        }
    }
    
    // === CACHED RECORD ===
    $cache = loadFromCache($domain, $qtype);
    if ($cache) {
        $cache = @unserialize($cache);
        $reply = $cache['response'];
        $reply[0] = $data[0];
        $reply[1] = $data[1];

        // $connection->send($cache['response']);
        $connection->send($reply);
        $stats['cache']++;
        // echo "  🗃  Reply (cache) $domain\n";

        saveStats($stats, $recentQueries);
        // printStats($stats);

        return;
    }

    // === UPSTREAM FORWARD ===
    $upstreamSock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_set_option($upstreamSock, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 2, 'usec' => 0]);
    socket_sendto($upstreamSock, $data, strlen($data), 0, UPSTREAM_DNS, UPSTREAM_PORT);

    $buf = '';
    $from = '';
    $port = 0;
    $len = @socket_recvfrom($upstreamSock, $buf, 512, 0, $from, $port);
    socket_close($upstreamSock);

    if ($len > 0) {
        $connection->send($buf);
        $ttl = extractTTL($buf);
        $cacheData = [
            'response' => $buf,
            'expires'  => time() + $ttl
        ];

        saveToCacheAsync($domain, $qtype, serialize($cacheData));
        $stats['upstream']++;
        // echo "  ↩ Reply (upstream cached) $domain\n";
    } else {
        // echo "  ✗ Timeout or no response from upstream\n";
    }


    saveStats($stats, $recentQueries);
    // printStats($stats);
};

// ====== Auto Cache Cleaner (setiap 10 menit) ======
$cacheCleaner = new Worker();
$cacheCleaner->name = 'DNS-Cache-Cleaner';
$cacheCleaner->onWorkerStart = function () {
    $cacheDir = __DIR__ . '/dns-cache';
    if (!is_dir($cacheDir)) return;

    echo "🧹 Cache cleaner aktif — interval 10 menit\n";

    // Loop background tiap 10 menit
    \Workerman\Timer::add(600, function () use ($cacheDir) {
        $now = time();
        $deleted = 0;

        foreach (glob("$cacheDir/*.bin") as $file) {
            if (!file_exists($file)) continue;
            $data = @unserialize(file_get_contents($file));
            if (!$data || !isset($data['expires'])) continue;

            if ($data['expires'] < $now) {
                unlink($file);
                $deleted++;
            }
        }

        if ($deleted > 0) {
            echo "🧹 Hapus $deleted cache kadaluarsa (" . date('H:i:s') . ")\n";
        }
    });
};

$httpWorker = new Worker('http://0.0.0.0:8080');
$httpWorker->name = 'DNS-Dashboard';
$httpWorker->onMessage = function ($connection, $request) {
    $path = $request->path();
    $data = loadStats();

    // JSON endpoint
    if ($path === '/stats.json') {
        $connection->send(json_encode($data, JSON_PRETTY_PRINT));
        return;
    }

    // HTML dashboard
    $stats = $data['stats'];
    $recentQueries = $data['recent_queries'];

    $html = "<html><head><title>DNS Server Dashboard</title>
    <meta http-equiv='refresh' content='3'>
    <style>
        body { font-family: Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 40px; }
        h1 { color: #58a6ff; }
        table { border-collapse: collapse; width: 60%; margin-top: 10px; }
        th, td { border: 1px solid #30363d; padding: 8px; text-align: left; }
        th { background: #161b22; color: #8b949e; }
        tr:nth-child(even) { background: #161b22; }
        .metric { font-size: 1.2em; margin-right: 30px; }
        .json-link { font-size: 0.9em; color: #58a6ff; text-decoration:none; }
        .json-link:hover { text-decoration:underline; }
    </style></head><body>
    <h1>🧠 penjaga.online - 103.178.174.235 - DNS Server Dashboard</h1>
    <div>
      <span class='metric'>Total Query: {$stats['total']}</span>
      <span class='metric'>Cache Hit: {$stats['cache']}</span>
      <span class='metric'>Upstream: {$stats['upstream']}</span>
      <span class='metric'>Local: {$stats['local']}</span>
    </div>
    <p><a href='/stats.json' class='json-link'>Lihat versi JSON →</a></p>
    <h2>🕵️‍♂️ Recent Queries</h2>
    <table>
      <tr><th>#</th><th>Domain</th></tr>";

    $i = 1;
    foreach (array_reverse($recentQueries) as $q) {
        $html .= "<tr><td>{$i}</td><td>{$q}</td></tr>";
        $i++;
    }

    $html .= "</table>
        <p style='color:#8b949e;font-size:0.9em;margin-top:20px'>Auto-refresh setiap 3 detik</p>
        <p style='color:#8b949e;font-size:0.9em;margin-top:20px'>by KoronX - https://penjaga.online - https://github.com/koronx/penjaga.online</p>
        </body></html>";

    $connection->send($html);
};

Worker::runAll();
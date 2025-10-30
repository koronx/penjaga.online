<?php
$bind_ip = "0.0.0.0";
$port = 53;
$upstream = "8.8.8.8"; // DNS publik (Google)

// Zona lokal
$local_records = [
    'example.local' => '192.168.1.100',
    'router.local'  => '192.168.1.1',
];

// Cache hasil query upstream
$cache = [];

$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
socket_bind($sock, $bind_ip, $port);

echo "DNS Server berjalan di udp://$bind_ip:$port (forward ke $upstream)\n";

while (true) {
    socket_recvfrom($sock, $buf, 512, 0, $client_ip, $client_port);
    $transaction_id = substr($buf, 0, 2);

    // Parse nama domain dari query
    $offset = 12;
    $domain = '';
    $len = ord($buf[$offset]);
    while ($len > 0) {
        $domain .= substr($buf, $offset + 1, $len) . '.';
        $offset += $len + 1;
        $len = ord($buf[$offset]);
    }
    $domain = strtolower(rtrim($domain, '.'));
    echo date('H:i:s') . " Query dari $client_ip: $domain\n";

    // 🔍 1. Cek zona lokal
    if (isset($local_records[$domain])) {
        $ip = $local_records[$domain];
        echo "→ Jawaban lokal: $ip\n";

        $flags = "\x81\x80";
        $questions = "\x00\x01";
        $answers = "\x00\x01";
        $auth = "\x00\x00";
        $add = "\x00\x00";

        $header = $transaction_id . $flags . $questions . $answers . $auth . $add;
        $query = substr($buf, 12);

        $answer = "\xc0\x0c"             // pointer ke nama domain
                . "\x00\x01"             // type A
                . "\x00\x01"             // class IN
                . "\x00\x00\x00\x3c"     // TTL 60 detik
                . "\x00\x04"             // panjang data
                . inet_pton($ip);        // IP address

        $response = $header . $query . $answer;
        socket_sendto($sock, $response, strlen($response), 0, $client_ip, $client_port);
        continue;
    }

    // 🧠 2. Cek cache
    if (isset($cache[$domain])) {
        echo "→ Cache ditemukan untuk $domain\n";
        $cached_response = $cache[$domain];
        // Ganti transaction ID dengan ID query klien
        $response = $transaction_id . substr($cached_response, 2);
        socket_sendto($sock, $response, strlen($response), 0, $client_ip, $client_port);
        continue;
    }

    // 🌐 3. Forward ke DNS upstream
    echo "→ Forward ke $upstream\n";
    $up_sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_sendto($up_sock, $buf, strlen($buf), 0, $upstream, 53);

    // Tunggu balasan
    $read = [$up_sock];
    $write = $except = [];
    $tv = ['sec' => 3, 'usec' => 0]; // timeout 3 detik
    $n = socket_select($read, $write, $except, $tv['sec'], $tv['usec']);

    if ($n > 0) {
        socket_recvfrom($up_sock, $up_buf, 512, 0, $uip, $uport);
        echo "← Balasan diterima dari $upstream, simpan ke cache\n";

        // Simpan di cache (pakai domain sebagai key)
        $cache[$domain] = $up_buf;

        // Ganti ID agar sesuai query awal
        $response = $transaction_id . substr($up_buf, 2);
        socket_sendto($sock, $response, strlen($response), 0, $client_ip, $client_port);
    } else {
        echo "⚠️ Timeout upstream\n";
    }

    socket_close($up_sock);
}
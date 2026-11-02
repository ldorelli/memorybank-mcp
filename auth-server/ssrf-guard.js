// SSRF guard for server-side fetches of client-controlled URLs.
//
// The auth server resolves CIMD clients (URL-as-client_id) and fetches their
// metadata document, and oidc-provider itself fetches a client's `jwks_uri`
// to verify `private_key_jwt` assertions. Both URLs arrive from an
// unauthenticated request, so without a guard an attacker can point them at a
// loopback, Docker-network, cloud-metadata (169.254.169.254) or other internal
// host and make us issue the GET. The CIMD draft asks servers for exactly this
// protection.
//
// Strategy: refuse non-https, resolve the host ourselves, reject any resolved
// address that is not a public unicast address, and connect using *those same
// results* so there's no resolve-then-reconnect gap for DNS rebinding. Callers
// additionally refuse redirects, require JSON, and cap the body.

import net from 'node:net';
import dns from 'node:dns';
import https from 'node:https';

// Non-public IPv4 ranges (RFC 5735/6598/1918/3927/5737/2544 and friends).
const blockedV4 = new net.BlockList();
for (const [addr, prefix] of [
    ['0.0.0.0', 8],        // "this" network / unspecified
    ['10.0.0.0', 8],       // RFC1918 private
    ['100.64.0.0', 10],    // RFC6598 CGNAT
    ['127.0.0.0', 8],      // loopback
    ['169.254.0.0', 16],   // link-local (incl. 169.254.169.254 cloud metadata)
    ['172.16.0.0', 12],    // RFC1918 private
    ['192.0.0.0', 24],     // IETF protocol assignments
    ['192.0.2.0', 24],     // TEST-NET-1
    ['192.168.0.0', 16],   // RFC1918 private
    ['198.18.0.0', 15],    // benchmarking
    ['198.51.100.0', 24],  // TEST-NET-2
    ['203.0.113.0', 24],   // TEST-NET-3
    ['224.0.0.0', 4],      // multicast
    ['240.0.0.0', 4],      // reserved (incl. 255.255.255.255 broadcast)
]) blockedV4.addSubnet(addr, prefix, 'ipv4');

// Non-public IPv6 ranges.
const blockedV6 = new net.BlockList();
blockedV6.addAddress('::', 'ipv6');  // unspecified
blockedV6.addAddress('::1', 'ipv6'); // loopback
for (const [addr, prefix] of [
    ['100::', 64],        // discard-only
    ['2001:db8::', 32],   // documentation
    ['fc00::', 7],        // unique local (ULA)
    ['fe80::', 10],       // link-local
    ['ff00::', 8],        // multicast
]) blockedV6.addSubnet(addr, prefix, 'ipv6');

function addressIsBlocked(address, family) {
    const fam = family === 6 || family === 'ipv6' ? 6 : 4;
    if (fam === 6) {
        // Unwrap IPv4-mapped (::ffff:a.b.c.d) so a private IPv4 can't hide
        // inside an IPv6 literal.
        const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
        if (mapped) return net.isIPv4(mapped[1]) ? blockedV4.check(mapped[1], 'ipv4') : true;
        return blockedV6.check(address, 'ipv6');
    }
    return blockedV4.check(address, 'ipv4');
}

// When a URL's host is already an IP literal, Node connects directly and never
// calls the `lookup` guard, so IP-literal targets must be checked up front.
// Returns true for a literal in a non-public range; false for a DNS name (those
// are caught at lookup time) or a public literal.
export function isBlockedIpLiteral(hostname) {
    const h = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
    const fam = net.isIP(h);
    if (!fam) return false; // not an IP literal
    return addressIsBlocked(h, fam);
}

// DNS lookup that validates EVERY resolved address before any connection is
// made, and hands the connection exactly those results. Usable as both node's
// https `lookup` option and oidc-provider's `httpOptions.dnsLookup`.
export function guardedLookup(hostname, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }
    dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
        if (err) return callback(err);
        if (!addresses || addresses.length === 0) {
            return callback(new Error(`no addresses for host ${hostname}`));
        }
        for (const a of addresses) {
            if (addressIsBlocked(a.address, a.family)) {
                const e = new Error(`blocked non-public address ${a.address} for host ${hostname}`);
                e.code = 'ESSRFBLOCKED';
                return callback(e);
            }
        }
        if (options && options.all) return callback(null, addresses);
        return callback(null, addresses[0].address, addresses[0].family);
    });
}

export function assertHttpsUrl(urlStr) {
    let url;
    try {
        url = new URL(urlStr);
    } catch {
        throw new Error('invalid URL');
    }
    if (url.protocol !== 'https:') throw new Error('only https URLs are allowed');
    if (isBlockedIpLiteral(url.hostname)) {
        const e = new Error(`blocked non-public host ${url.hostname}`);
        e.code = 'ESSRFBLOCKED';
        throw e;
    }
    return url;
}

// Hardened GET for client-controlled metadata documents (CIMD). https-only,
// resolves + validates the host, refuses redirects, requires JSON, and caps the
// body before parsing. Resolves to the parsed JSON, rejects otherwise.
export function fetchJsonFromPublicUrl(urlStr, { timeoutMs = 5000, maxBytes = 256 * 1024 } = {}) {
    const url = assertHttpsUrl(urlStr);
    return new Promise((resolve, reject) => {
        let settled = false;
        const fail = (err) => {
            if (settled) return;
            settled = true;
            reject(err);
        };
        const done = (val) => {
            if (settled) return;
            settled = true;
            resolve(val);
        };

        const req = https.request(url, {
            method: 'GET',
            lookup: guardedLookup,
            headers: { accept: 'application/json' },
            timeout: timeoutMs,
        }, (res) => {
            const status = res.statusCode || 0;
            // Refuse redirects outright rather than following them to an
            // internal target that the host check never saw.
            if (status >= 300 && status < 400) {
                res.destroy();
                return fail(new Error(`redirect not allowed (HTTP ${status})`));
            }
            if (status !== 200) {
                res.destroy();
                return fail(new Error(`HTTP ${status}`));
            }
            const ct = String(res.headers['content-type'] || '').toLowerCase();
            if (!ct.includes('application/json')) {
                res.destroy();
                return fail(new Error(`unexpected content-type: ${ct || '(none)'}`));
            }
            let size = 0;
            const chunks = [];
            res.on('data', (chunk) => {
                size += chunk.length;
                if (size > maxBytes) {
                    res.destroy();
                    fail(new Error('response body too large'));
                }
                else chunks.push(chunk);
            });
            res.on('error', fail);
            res.on('end', () => {
                try {
                    done(JSON.parse(Buffer.concat(chunks).toString('utf8')));
                } catch {
                    fail(new Error('invalid JSON body'));
                }
            });
        });
        req.on('error', fail);
        req.on('timeout', () => req.destroy(new Error('request timed out')));
        req.end();
    });
}

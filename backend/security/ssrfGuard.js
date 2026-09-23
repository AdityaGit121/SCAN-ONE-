const dns = require('dns').promises;
const net = require('net');

/**
 * Normalizes alternative IP encodings (e.g. integer, octal, hex) into standard dotted-decimal IPv4
 */
function parseAnyIPv4(host) {
  if (!host) return null;
  const trimmed = host.trim().toLowerCase();

  // If already standard dotted-decimal, test directly
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
    return trimmed;
  }

  // Pure integer format (e.g., 2130706433 = 127.0.0.1)
  if (/^\d{8,10}$/.test(trimmed)) {
    const num = Number(trimmed);
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      return `${(num >>> 24) & 255}.${(num >>> 16) & 255}.${(num >>> 8) & 255}.${num & 255}`;
    }
  }

  // Pure hex format (e.g., 0x7f000001)
  if (/^0x[0-9a-f]{1,8}$/i.test(trimmed)) {
    const num = parseInt(trimmed, 16);
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      return `${(num >>> 24) & 255}.${(num >>> 16) & 255}.${(num >>> 8) & 255}.${num & 255}`;
    }
  }

  // Dotted hex / octal parts (e.g. 0177.0.0.1 or 0x7f.0.0.1)
  const parts = trimmed.split('.');
  if (parts.length === 4) {
    const parsed = parts.map(p => {
      if (/^0x[0-9a-f]+$/i.test(p)) return parseInt(p, 16);
      if (/^0[0-7]+$/.test(p) && p.length > 1) return parseInt(p, 8);
      if (/^\d+$/.test(p)) return parseInt(p, 10);
      return NaN;
    });

    if (parsed.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
      return parsed.join('.');
    }
  }

  return null;
}

/**
 * SSRF Guard - Military-Grade validation against private IPs, loopback, link-local,
 * cloud metadata endpoints, container gateways, and IPv4-mapped IPv6 notations.
 */
function isPrivateOrReservedIP(rawIp) {
  if (!rawIp) return true;

  let normalized = String(rawIp).trim().toLowerCase();

  // Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (normalized.startsWith('::ffff:')) {
    const mapped = normalized.substring(7);
    if (net.isIPv4(mapped)) {
      return isPrivateOrReservedIP(mapped);
    }
    const hexParts = mapped.split(':');
    if (hexParts.length === 2) {
      const p1 = parseInt(hexParts[0], 16);
      const p2 = parseInt(hexParts[1], 16);
      if (!isNaN(p1) && !isNaN(p2)) {
        const ip4 = `${(p1 >> 8) & 0xff}.${p1 & 0xff}.${(p2 >> 8) & 0xff}.${p2 & 0xff}`;
        return isPrivateOrReservedIP(ip4);
      }
    }
  }

  // Attempt alternative IPv4 decoding
  const decodedIpv4 = parseAnyIPv4(normalized) || (net.isIPv4(normalized) ? normalized : null);

  if (decodedIpv4) {
    const parts = decodedIpv4.split('.').map(Number);
    // 0.0.0.0/8 (Current network)
    if (parts[0] === 0) return true;
    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true;
    // 10.0.0.0/8 (Private RFC 1918)
    if (parts[0] === 10) return true;
    // 172.16.0.0/12 (Private RFC 1918: 172.16.0.0 - 172.31.255.255)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16 (Private RFC 1918)
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 169.254.0.0/16 (Link-local & AWS/GCP/Azure/Oracle cloud metadata)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 100.64.0.0/10 (Carrier-grade NAT RFC 6598)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    // 100.100.100.200 (Alibaba Cloud metadata)
    if (parts[0] === 100 && parts[1] === 100 && parts[2] === 100) return true;
    // 192.0.0.0/24 (IETF Protocol Assignments)
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return true;
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET documentation)
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true;
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true;
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true;
    // 198.18.0.0/15 (Benchmarking)
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true;
    // 224.0.0.0/4 (Multicast / Class D) & 240.0.0.0/4 (Reserved / Class E)
    if (parts[0] >= 224) return true;
    // 255.255.255.255 (Broadcast)
    if (parts[0] === 255) return true;
    return false;
  }

  // IPv6 checks
  if (net.isIPv6(normalized)) {
    if (
      normalized === '::1' ||
      normalized === '::' ||
      normalized.startsWith('fe80:') || // link-local
      normalized.startsWith('fc00:') || // unique local
      normalized.startsWith('fd00:') || // unique local
      normalized.startsWith('ff00:') || // multicast
      normalized.startsWith('2001:db8:') // documentation IPv6
    ) {
      return true;
    }
  }

  return false;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  '169.254.169.254',
  'instance-data',
  'local',
  'broadcasthost',
  'docker.for.mac.localhost',
  'docker.for.win.localhost',
  'kubernetes.default',
  'kubernetes.default.svc'
]);

async function validateUrlForSafeFetch(urlString) {
  let normalizedInput = (urlString || '').trim();
  if (!/^https?:\/\//i.test(normalizedInput)) {
    normalizedInput = 'https://' + normalizedInput;
  }

  let url;
  try {
    url = new URL(normalizedInput);
  } catch (e) {
    return { safe: false, reason: 'Malformed URL structure' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { safe: false, reason: `Disallowed protocol: ${url.protocol} (only http/https allowed)` };
  }

  const hostname = url.hostname.toLowerCase();

  // Strip IPv6 brackets if present for hostname checks
  const cleanHost = hostname.replace(/^\[|\]$/g, '');

  // Check blocked hostnames and suffixes
  if (
    BLOCKED_HOSTNAMES.has(cleanHost) ||
    cleanHost.endsWith('.local') ||
    cleanHost.endsWith('.internal') ||
    cleanHost.endsWith('.localhost') ||
    cleanHost.endsWith('.cluster.local')
  ) {
    return { safe: false, reason: `Blocked private or internal metadata hostname: ${cleanHost}` };
  }

  // Test if hostname is raw or alternative IP notation (decimal, hex, octal)
  const decodedRawIp = parseAnyIPv4(cleanHost);
  if (decodedRawIp) {
    if (isPrivateOrReservedIP(decodedRawIp)) {
      return { safe: false, reason: `Direct access to private/loopback IP forbidden: ${cleanHost} (${decodedRawIp})` };
    }
    return { safe: true, ip: decodedRawIp, url: url.href };
  }

  if (net.isIP(cleanHost)) {
    if (isPrivateOrReservedIP(cleanHost)) {
      return { safe: false, reason: `Direct access to private/loopback IP forbidden: ${cleanHost}` };
    }
    return { safe: true, ip: cleanHost, url: url.href };
  }

  // DNS resolution check to prevent DNS rebinding to private/metadata IPs
  try {
    const resolved = await dns.lookup(cleanHost, { all: true });
    for (const record of resolved) {
      if (isPrivateOrReservedIP(record.address)) {
        return { safe: false, reason: `Hostname resolves to private/reserved IP: ${record.address}` };
      }
    }
    return { safe: true, ip: resolved[0]?.address, url: url.href };
  } catch (err) {
    // If the host is not found in DNS (e.g. defunct phishing domain / NXDOMAIN),
    // it cannot reach internal infrastructure (SSRF safe), but should still be analyzed for phishing heuristics.
    return { safe: true, unresolved: true, url: url.href, reason: `Public DNS unresolvable: ${err.message}` };
  }
}

module.exports = {
  parseAnyIPv4,
  isPrivateOrReservedIP,
  validateUrlForSafeFetch
};


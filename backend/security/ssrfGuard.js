const dns = require('dns').promises;
const net = require('net');

/**
 * SSRF Guard - Strict validation against private IPs, loopback, link-local,
 * cloud metadata endpoints, and IPv4-mapped IPv6 notations.
 */
function isPrivateOrReservedIP(ip) {
  if (!ip) return true;

  let normalized = String(ip).trim().toLowerCase();

  // Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (normalized.startsWith('::ffff:')) {
    const mapped = normalized.substring(7);
    if (net.isIPv4(mapped)) {
      return isPrivateOrReservedIP(mapped);
    }
    // Hex notation (e.g. ::ffff:7f00:0001)
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

  // IPv4 checks
  if (net.isIPv4(normalized)) {
    const parts = normalized.split('.').map(Number);
    // 0.0.0.0/8
    if (parts[0] === 0) return true;
    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true;
    // 10.0.0.0/8 (Private)
    if (parts[0] === 10) return true;
    // 172.16.0.0/12 (Private: 172.16.0.0 - 172.31.255.255)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 169.254.0.0/16 (Link-local & AWS/GCP metadata)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 100.64.0.0/10 (Carrier-grade NAT)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET)
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true;
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true;
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true;
    // 224.0.0.0/4 (Multicast / Reserved)
    if (parts[0] >= 224) return true;
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
      normalized.startsWith('ff00:')    // multicast
    ) {
      return true;
    }
  }

  return false;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  '169.254.169.254',
  'instance-data',
  'local',
  'broadcasthost'
]);

async function validateUrlForSafeFetch(urlString) {
  let url;
  try {
    url = new URL(urlString);
  } catch (e) {
    return { safe: false, reason: 'Malformed URL structure' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { safe: false, reason: `Disallowed protocol: ${url.protocol} (only http/https allowed)` };
  }

  const hostname = url.hostname.toLowerCase();

  // Strip IPv6 brackets if present for hostname checks
  const cleanHost = hostname.replace(/^\[|\]$/g, '');

  // Check blocked hostnames
  if (BLOCKED_HOSTNAMES.has(cleanHost) || cleanHost.endsWith('.local') || cleanHost.endsWith('.internal')) {
    return { safe: false, reason: `Blocked private or metadata hostname: ${cleanHost}` };
  }

  // If host is raw IP
  if (net.isIP(cleanHost)) {
    if (isPrivateOrReservedIP(cleanHost)) {
      return { safe: false, reason: `Direct access to private/loopback IP forbidden: ${cleanHost}` };
    }
    return { safe: true, ip: cleanHost, url: url.href };
  }

  // DNS resolution check to prevent DNS rebinding to private IPs
  try {
    const resolved = await dns.lookup(cleanHost, { all: true });
    for (const record of resolved) {
      if (isPrivateOrReservedIP(record.address)) {
        return { safe: false, reason: `Hostname resolves to private/reserved IP: ${record.address}` };
      }
    }
    return { safe: true, ip: resolved[0]?.address, url: url.href };
  } catch (err) {
    return { safe: false, reason: `DNS resolution failed: ${err.message}` };
  }
}

module.exports = {
  isPrivateOrReservedIP,
  validateUrlForSafeFetch
};

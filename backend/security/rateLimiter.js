/**
 * Military-Grade In-Memory Sliding Window Rate Limiter
 * Guards against API flooding, credential stuffing, and DoS attacks.
 */
class SlidingWindowRateLimiter {
  constructor(windowMs = 60000, maxRequests = 60) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.requests = new Map();

    // Periodic cleanup of stale IP buckets every 2 minutes
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [ip, timestamps] of this.requests.entries()) {
        const active = timestamps.filter(t => now - t < this.windowMs);
        if (active.length === 0) {
          this.requests.delete(ip);
        } else {
          this.requests.set(ip, active);
        }
      }
    }, 120000);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  middleware(customMax = null, message = 'Too many requests. Rate limit exceeded.') {
    return (req, res, next) => {
      const limit = customMax || this.maxRequests;
      const clientIp = (
        req.headers['x-forwarded-for']?.split(',')[0] ||
        req.socket.remoteAddress ||
        '127.0.0.1'
      ).trim();

      const now = Date.now();
      let timestamps = this.requests.get(clientIp) || [];
      timestamps = timestamps.filter(t => now - t < this.windowMs);

      if (timestamps.length >= limit) {
        const oldest = timestamps[0];
        const retryAfterSec = Math.ceil((oldest + this.windowMs - now) / 1000);
        res.setHeader('Retry-After', retryAfterSec);
        res.setHeader('X-RateLimit-Limit', limit);
        res.setHeader('X-RateLimit-Remaining', 0);
        return res.status(429).json({
          success: false,
          error: message,
          retryAfterSeconds: retryAfterSec
        });
      }

      timestamps.push(now);
      this.requests.set(clientIp, timestamps);

      res.setHeader('X-RateLimit-Limit', limit);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, limit - timestamps.length));
      next();
    };
  }
}

// Global Limiter (60 scans/min) & Strict Limiter (15 key tests/min)
const scanRateLimiter = new SlidingWindowRateLimiter(60000, 60);
const authRateLimiter = new SlidingWindowRateLimiter(60000, 15);

module.exports = {
  SlidingWindowRateLimiter,
  scanRateLimiter,
  authRateLimiter
};

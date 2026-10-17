package traefik_http_knock

import (
	"fmt"
	"strconv"
)

// loginFailureKey is the Redis key for failed password attempts from one IP.
// The realm keeps counters isolated between middleware instances that share a
// Redis database.
func loginFailureKey(prefix, realm, clientIP string) string {
	return scopedKey(prefix, realm, "login", clientIP)
}

// loginAllowed reports whether the client may attempt a password login. A
// Redis failure is returned to the caller so the login path can fail closed:
// without the counter, rate limiting cannot be guaranteed.
func (m *middleware) loginAllowed(clientIP string) (bool, error) {
	if m.cfg.maxLoginAttempts <= 0 {
		return true, nil
	}
	value, ok, err := m.redis.getValue(loginFailureKey(m.cfg.keyPrefix, m.cfg.realm, clientIP))
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil
	}
	count, err := strconv.Atoi(value)
	if err != nil {
		// A malformed counter must not turn into an unlimited login window.
		return false, fmt.Errorf("http-knock: invalid login counter value")
	}
	return count < m.cfg.maxLoginAttempts, nil
}

// recordLoginFailure increments the per-IP failure counter. INCR is not
// idempotent, so it uses do() instead of doIdempotent(); a retry could otherwise
// count the same failure twice.
func (m *middleware) recordLoginFailure(clientIP string) error {
	if m.cfg.maxLoginAttempts <= 0 {
		return nil
	}
	key := loginFailureKey(m.cfg.keyPrefix, m.cfg.realm, clientIP)
	count, err := m.redis.incr(key)
	if err != nil {
		return err
	}
	if count == 1 {
		if err := m.redis.expire(key, m.cfg.loginWindow); err != nil {
			return err
		}
	}
	return nil
}

func (m *middleware) clearLoginFailures(clientIP string) error {
	if m.cfg.maxLoginAttempts <= 0 {
		return nil
	}
	return m.redis.del(loginFailureKey(m.cfg.keyPrefix, m.cfg.realm, clientIP))
}

func (m *middleware) acquireLoginSlot() bool {
	if m.cfg.maxConcurrentLogins <= 0 {
		return true
	}
	select {
	case m.loginSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (m *middleware) releaseLoginSlot() {
	if m.cfg.maxConcurrentLogins <= 0 {
		return
	}
	select {
	case <-m.loginSlots:
	default:
	}
}

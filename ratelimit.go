package traefik_http_knock

// loginFailureKey is the Redis key for login attempts from one IP.
// The realm keeps counters isolated between middleware instances that share a
// Redis database.
func loginFailureKey(prefix, realm, clientIP string) string {
	return scopedKey(prefix, realm, "login", clientIP)
}

// reserveLoginAttempt counts one login attempt and reports whether the client
// may continue. Counting before password verification avoids the check-then-
// increment race that let a concurrent burst exceed maxLoginAttempts.
//
// The counter is created with SET NX EX, so it has a TTL from the first
// attempt. Every attempt refreshes that TTL; if EXPIRE fails anyway the key is
// deleted, because a counter without a TTL would lock the IP out forever once it
// reaches the limit. A successful login deletes the counter.
func (m *middleware) reserveLoginAttempt(clientIP string) (bool, error) {
	if m.cfg.maxLoginAttempts <= 0 {
		return true, nil
	}

	key := loginFailureKey(m.cfg.keyPrefix, m.cfg.realm, clientIP)
	if _, err := m.redis.setNXEx(key, "0", m.cfg.loginWindow); err != nil {
		return false, err
	}

	count, err := m.redis.incr(key)
	if err != nil {
		return false, err
	}
	if err := m.redis.expire(key, m.cfg.loginWindow); err != nil {
		// A TTL-less counter is worse than losing the failure count: delete it
		// so the client is not locked out permanently.
		_ = m.redis.del(key)
		return false, err
	}

	return count <= int64(m.cfg.maxLoginAttempts), nil
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

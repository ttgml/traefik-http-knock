package traefik_http_knock

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestLogDecisionfHonorsLogDecisions(t *testing.T) {
	var buf bytes.Buffer
	m := &middleware{
		cfg:    &settings{logDecisions: false},
		logger: log.New(&buf, "", 0),
	}

	m.logDecisionf("hidden %d", 1)
	if buf.Len() != 0 {
		t.Fatalf("logDecisionf wrote %q while disabled", buf.String())
	}

	m.cfg.logDecisions = true
	m.logDecisionf("shown %d", 1)
	if got := buf.String(); !strings.Contains(got, "shown 1") {
		t.Fatalf("logDecisionf output = %q, want it to contain %q", got, "shown 1")
	}
}

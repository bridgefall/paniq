package envelope

import (
	"context"
	"log/slog"
	"net"
	"time"
)

func resolveLogger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}

func logTransportShared(logger *slog.Logger, limiter *logLimiter, now time.Time, dir string, addr net.Addr, frameLen int, innerLen int, padLen int, clamped bool) {
	if limiter == nil {
		return
	}
	l := resolveLogger(logger)
	if !l.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	key := "transport_" + dir
	if !limiter.Allow(key, now) {
		return
	}
	target := ""
	if addr != nil {
		target = addr.String()
	}
	clampedVal := 0
	if clamped {
		clampedVal = 1
	}
	l.Debug("envelope transport", "dir", dir, "addr", target, "frame", frameLen, "inner", innerLen, "pad", padLen, "clamped", clampedVal)
}

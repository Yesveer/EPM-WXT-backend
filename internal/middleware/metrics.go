package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-agent-backend/internal/metrics"
)

func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/metrics" {
			c.Next()
			return
		}

		metrics.HTTPRequestsInFlight.Inc()
		start := time.Now()

		c.Next()

		duration := time.Since(start).Seconds()
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}

		metrics.HTTPRequestsInFlight.Dec()
		metrics.HTTPRequestsTotal.WithLabelValues(
			c.Request.Method,
			path,
			strconv.Itoa(c.Writer.Status()),
		).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(c.Request.Method, path).Observe(duration)
	}
}

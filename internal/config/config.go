package config

import (
	"os"
)

type Config struct {
	// NetFlow listener settings
	NetFlowHost string
	NetFlowPort int

	// Web server settings
	WebHost string
	WebPort int

	// Storage settings
	MaxFlows int
}

func LoadConfig() *Config {
	return &Config{
		NetFlowHost: getEnv("NETFLOW_HOST", "0.0.0.0"),
		NetFlowPort: parseInt(getEnv("NETFLOW_PORT", "2055")),
		WebHost:     getEnv("WEB_HOST", "0.0.0.0"),
		WebPort:     parseInt(getEnv("WEB_PORT", "8080")),
		MaxFlows:    parseInt(getEnv("MAX_FLOWS", "10000")),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseInt(s string) int {
	if s == "" {
		return 0
	}
	// Simple parse implementation
	var n int
	sign := 1
	for i, c := range s {
		if c == '-' {
			sign = -1
			continue
		}
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if i > 0 && n > 2147483647 {
			return 0
		}
	}
	return n * sign
}

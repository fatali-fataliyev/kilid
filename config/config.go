package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type config struct {
	Iterations int `json:"iterations"`
	Memory     int `json:"memory"`
	Threads    int `json:"threads"`
	KeyLen     int `json:"key_len"`
}

func Load() (map[string]int, error) {
	f, err := os.ReadFile("argonConfig.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var c config
	if err := json.Unmarshal(f, &c); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cfg := map[string]int{
		"iterations": c.Iterations,
		"memory":     c.Memory,
		"threads":    c.Threads,
		"keyLen":     c.KeyLen,
	}

	return cfg, nil
}

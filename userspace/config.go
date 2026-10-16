package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Mode            string          `toml:"mode"`
	Log             LogConfig       `toml:"log"`
	Filter          FilterConfig    `toml:"filter"`
	Rates           RatesConfig     `toml:"rates"`
	Container       ContainerConfig `toml:"container"`
	Context         ContextConfig   `toml:"context"`
	DisabledActions []string        `toml:"disabled_actions"`
}

type LogConfig struct {
	Path       string `toml:"path"`
	MaxBytes   int64  `toml:"max_bytes"`
	MaxBackups int    `toml:"max_backups"`
	Level      string `toml:"level"`
}

type FilterConfig struct {
	CommAllowlist   []string `toml:"comm_allowlist"`
	CgroupAllowlist []uint64 `toml:"cgroup_allowlist"`
}

type RatesConfig struct {
	EventsPerSec int `toml:"events_per_sec"`
	Burst        int `toml:"burst"`
}

type ContainerConfig struct {
	CacheMaxEntries int `toml:"cache_max_entries"`
}

type ContextConfig struct {
	LineageMaxDepth  int `toml:"lineage_max_depth"`
	LineageCacheSize int `toml:"lineage_cache_size"`
	CgroupCacheSize  int `toml:"cgroup_cache_size"`
}

func DefaultConfig() Config {
	return Config{
		Mode: "audit",
		Log: LogConfig{
			Path:       "/var/log/ebpf_edr.json",
			MaxBytes:   50 * 1024 * 1024,
			MaxBackups: 5,
			Level:      "info",
		},
		Rates:     RatesConfig{EventsPerSec: 200, Burst: 400},
		Container: ContainerConfig{CacheMaxEntries: 5000},
		Context:   ContextConfig{LineageMaxDepth: 16, LineageCacheSize: 20000, CgroupCacheSize: 5000},
	}
}

// LoadConfig reads TOML from path. Missing file is not an error — defaults are returned.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("stat config: %w", err)
	}
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		keys := make([]string, 0, len(undec))
		for _, k := range undec {
			keys = append(keys, k.String())
		}
		return cfg, fmt.Errorf("unknown config keys: %s", strings.Join(keys, ", "))
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	switch c.Mode {
	case "", "audit":
		c.Mode = "audit"
	case "enforce":
		return errors.New("mode=enforce is not implemented in this build; only 'audit' is supported")
	default:
		return fmt.Errorf("invalid mode %q (allowed: audit)", c.Mode)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	case "":
		c.Log.Level = "info"
	default:
		return fmt.Errorf("invalid log.level %q", c.Log.Level)
	}
	if c.Log.Path == "" {
		return errors.New("log.path must not be empty")
	}
	if c.Log.MaxBytes < 0 {
		return errors.New("log.max_bytes must be >= 0")
	}
	if c.Log.MaxBackups < 0 {
		return errors.New("log.max_backups must be >= 0")
	}
	if c.Rates.EventsPerSec < 0 || c.Rates.Burst < 0 {
		return errors.New("rates.* must be >= 0")
	}
	if c.Rates.EventsPerSec > 0 && c.Rates.Burst == 0 {
		return errors.New("rates.burst must be > 0 when rates.events_per_sec > 0")
	}
	if c.Container.CacheMaxEntries < 1 {
		return errors.New("container.cache_max_entries must be >= 1")
	}
	if c.Context.LineageMaxDepth < 1 || c.Context.LineageMaxDepth > 64 {
		return errors.New("context.lineage_max_depth must be 1..64")
	}
	if c.Context.LineageCacheSize < 1 {
		return errors.New("context.lineage_cache_size must be >= 1")
	}
	if c.Context.CgroupCacheSize < 1 {
		return errors.New("context.cgroup_cache_size must be >= 1")
	}
	for _, cg := range c.Filter.CgroupAllowlist {
		if cg == 0 {
			return errors.New("filter.cgroup_allowlist must not contain 0")
		}
	}
	for _, cm := range c.Filter.CommAllowlist {
		if len(cm) == 0 || len(cm) > 15 {
			return fmt.Errorf("filter.comm_allowlist entry %q: length must be 1..15", cm)
		}
	}
	return nil
}

// ApplyEnvAndFlags overlays env vars then CLI flags on top of the file config.
// Precedence: CLI > env > file > defaults.
func (c *Config) ApplyEnvAndFlags(logPath, logLevel, mode string) {
	if v := os.Getenv("EDR_LOG_PATH"); v != "" {
		c.Log.Path = v
	}
	if v := os.Getenv("EDR_LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
	if v := os.Getenv("EDR_MODE"); v != "" {
		c.Mode = v
	}
	if logPath != "" {
		c.Log.Path = logPath
	}
	if logLevel != "" {
		c.Log.Level = logLevel
	}
	if mode != "" {
		c.Mode = mode
	}
}

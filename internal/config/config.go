package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Output struct {
		Directory string `yaml:"directory"`
		File      string `yaml:"file"`
	} `yaml:"output"`
	Performance struct {
		LogIntervalMs  int `yaml:"log_interval_ms"`
		InflightPerLog int `yaml:"inflight_per_log"`
		ParseWorkers   int `yaml:"parse_workers"`
		StartOffset    int `yaml:"start_offset"`
		MaxLogs        int `yaml:"max_logs"`
		BatchWrite     int `yaml:"batch_write"`
		CheckWorkers   int `yaml:"check_workers"`
		CheckTimeoutMs int `yaml:"check_timeout_ms"`
	} `yaml:"performance"`
	Sources struct {
		Logs []string `yaml:"logs"`
	} `yaml:"sources"`
	Filters struct {
		ZeroSpam bool `yaml:"zero_spam"`
	} `yaml:"filters"`
	Throttle struct {
		Enabled         bool `yaml:"enabled"`
		CPUPercent      float64 `yaml:"cpu_percent"`
		RAMPercent      float64 `yaml:"ram_percent"`
		CheckIntervalMs int  `yaml:"check_interval_ms"`
		SleepMs         int  `yaml:"sleep_ms"`
	} `yaml:"throttle"`
}

func Default() *Config {
	c := &Config{}
	c.Output.Directory = "./output"
	c.Output.File = "alive.txt"
	c.Performance.LogIntervalMs = 1000
	c.Performance.InflightPerLog = 64
	c.Performance.ParseWorkers = 6
	c.Performance.StartOffset = 800000
	c.Performance.MaxLogs = 4
	c.Performance.BatchWrite = 5000
	c.Performance.CheckWorkers = 4000
	c.Performance.CheckTimeoutMs = 600
	c.Sources.Logs = []string{
		"https://ct.googleapis.com/logs/us1/argon2026h2",
		"https://ct.googleapis.com/logs/us1/argon2025h2",
		"https://ct.googleapis.com/logs/eu1/xenon2026h2",
		"https://ct.googleapis.com/logs/eu1/xenon2025h2",
	}
	c.Filters.ZeroSpam = true
	c.Throttle.Enabled = true
	c.Throttle.CPUPercent = 80
	c.Throttle.RAMPercent = 80
	c.Throttle.CheckIntervalMs = 500
	c.Throttle.SleepMs = 50
	return c
}

func Load(path string) (*Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, err
	}
	if c.Performance.InflightPerLog <= 0 {
		c.Performance.InflightPerLog = 64
	}
	if c.Performance.ParseWorkers <= 0 {
		c.Performance.ParseWorkers = 6
	}
	if c.Performance.CheckWorkers <= 0 {
		c.Performance.CheckWorkers = 4000
	}
	if len(c.Sources.Logs) == 0 {
		c.Sources.Logs = Default().Sources.Logs
	}
	return c, nil
}

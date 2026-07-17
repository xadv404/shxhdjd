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
		CheckWorkers   int `yaml:"check_workers"`
		CheckTimeoutMs int `yaml:"check_timeout_ms"`
	} `yaml:"performance"`
	Throttle struct {
		Enabled         bool    `yaml:"enabled"`
		CPUPercent      float64 `yaml:"cpu_percent"`
		RAMPercent      float64 `yaml:"ram_percent"`
		CheckIntervalMs int     `yaml:"check_interval_ms"`
		SleepMs         int     `yaml:"sleep_ms"`
	} `yaml:"throttle"`
}

func Default() *Config {
	c := &Config{}
	c.Output.Directory = "./output"
	c.Output.File = "alive.txt"
	c.Performance.LogIntervalMs = 1000
	c.Performance.CheckWorkers = 4000
	c.Performance.CheckTimeoutMs = 600
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
	if c.Performance.CheckWorkers <= 0 {
		c.Performance.CheckWorkers = 4000
	}
	if c.Performance.CheckTimeoutMs <= 0 {
		c.Performance.CheckTimeoutMs = 600
	}
	return c, nil
}

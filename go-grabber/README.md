# domain-grabber (Go)

Version Go max-perf du grabber CT — optimisée pour **6 cores / 6 Go RAM / ~1.7 Gbps**.

## Build

```bash
cd go-grabber
go build -o grabber ./cmd/grabber
```

## Config

`config.yaml` est déjà tuné au max :

| Param | Valeur | Rôle |
|------|--------|------|
| `inflight_per_log` | 64 | requêtes CT parallèles / log |
| `max_logs` | 4 | argon/xenon Google |
| `start_offset` | 800000 | profondeur historique |
| `check_workers` | 4000 | dial TCP parallèles |
| `check_timeout_ms` | 600 | timeout port |
| `cpu_percent` / `ram_percent` | 80 | throttle auto |

Quand CPU ou RAM dépasse **80%**, le pipeline dort par pas de 50 ms jusqu’à redescendre.

## Usage

```bash
# Grab CT → output/domains.txt
./grabber grab -c config.yaml

# Stop auto après 60s
./grabber grab -t 60

# Check ports TCP 80/443
./grabber check -i output/domains.txt -o output/alive.txt
```

## Tips VPS

```bash
ulimit -n 1048576
./grabber grab
```

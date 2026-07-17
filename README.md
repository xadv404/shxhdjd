# domain-grabber (Go)

Grabber CT max-perf — **6 cores / 6 Go RAM / ~1.7 Gbps**.

## Build

```bash
go build -o grabber ./cmd/grabber
```

## Config

`config.yaml` est déjà présent et tuné au max :

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
ulimit -n 1048576
./grabber grab
./grabber grab -t 60
./grabber check -i output/domains.txt -o output/alive.txt
```

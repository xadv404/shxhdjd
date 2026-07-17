# domain-grabber (Go)

Check TCP **80/443** max-perf — **6 cores / 6 Go RAM / ~1.7 Gbps**.

Tu fournis toi-même le `.txt` de domaines (1 par ligne).

## Build

```bash
go build -o grabber ./cmd/grabber
```

## Config (`config.yaml`)

| Param | Valeur | Rôle |
|------|--------|------|
| `check_workers` | 4000 | dial TCP parallèles |
| `check_timeout_ms` | 600 | timeout port |
| `cpu_percent` / `ram_percent` | 80 | throttle auto |

Quand CPU ou RAM dépasse **80%**, le pipeline dort par pas de 50 ms.

## Usage

```bash
ulimit -n 1048576
./grabber -i domains.txt -o alive.txt
```

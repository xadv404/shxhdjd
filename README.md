# domain-grabber (Go)

Grab CT max-perf — **6 cores / 6 Go RAM / ~1.7 Gbps**.

Tout est dans `config.yaml`. Aucun flag.

## Build

```bash
go build -o grabber ./cmd/grabber
```

## Usage

```bash
ulimit -n 1048576
./grabber
```

Écrit dans `output/domains.txt`. Stop avec `Ctrl+C`.

Throttle auto si CPU ou RAM > **80%**.

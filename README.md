# domain-grabber (Go)

Grab CT + check TCP — **6 cores / 6 Go RAM / ~1.7 Gbps**.

## Build

```bash
go build -o grabber ./cmd/grabber
```

## Usage

```bash
ulimit -n 1048576

# Grab CT → écrit domains.txt en temps réel
./grabber grab

# Stop = Ctrl+C (les domaines sont déjà dans le fichier)

# Check ports 80/443 sur output/domains.txt → output/alive.txt
./grabber check
```

Tout le tuning est dans `config.yaml` (pas d’autres flags).
Throttle auto si CPU ou RAM > **80%**.

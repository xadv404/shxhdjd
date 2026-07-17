# domain-grabber (Go)

Lance le binaire — **grab CT + check TCP 80/443** en même temps.

## Build

```bash
go build -o grabber ./cmd/grabber
```

## Usage

```bash
ulimit -n 1048576
./grabber
```

- `output/domains.txt` — tous les domaines filtrés (temps réel)
- `output/alive.txt` — ceux avec port 80 ou 443 ouvert (temps réel)

Stop = **Ctrl+C**. Config dans `config.yaml`.

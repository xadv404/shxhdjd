# domain-grabber (Go)

Lance le binaire — grab CT + check TCP 80/443.

## Windows

`grabber.exe` est déjà dans le repo. Ou :

```bat
build.bat
grabber.exe
```

## Linux / macOS

```bash
go build -o grabber ./cmd/grabber
ulimit -n 1048576
./grabber
```

Écrit uniquement `output/alive.txt` (domaines avec 80 ou 443 ouverts), en temps réel.

Stop = **Ctrl+C**. Config dans `config.yaml`.

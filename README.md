# Frenzynet

## Deploy Push Helper

Use the retry/backoff deploy helper when GitHub push is flaky:

```bash
./scripts/deploy-github.sh --branch main
```

Enable optional DNS fallback (`/etc/hosts` temporary block) if resolver issues happen:

```bash
./scripts/deploy-github.sh --branch main --resolver-fallback
```

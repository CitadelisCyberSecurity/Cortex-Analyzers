# Cortex-Analyzers

Cortex Analyzers Repository

## Creating a new analyzer

```bash
python utils/new-analyzer.py --name MyService --datatypes ip,domain
```

See [docs/creating-an-analyzer.md](docs/creating-an-analyzer.md) for the full workflow: filling in the template, taxonomy conventions for Shuffle → IRIS, tests, and CI.

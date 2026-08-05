# Architecture

## Pipeline

```
CLI (cli.py)
  -> Scanner.run()
       -> validate_url()      [Stage 2]
       -> fetch_headers()     [Stage 2]
       -> detect_headers()    [Stage 3 + 4]
       -> score_risk()        [Stage 5]
       -> build report        [Stage 6]
```

## Why this structure

- **`src/` layout** - keeps the installable package separate from repo
  root clutter (README, tests, docs) and prevents accidentally testing
  against an uninstalled copy of the code.
- **`core/models.py` defined first** - every stage after this one
  consumes/produces `ScanResult` and `HeaderFinding` objects instead of
  raw dicts. This is the "contract" the rest of the project is built
  against.
- **`Scanner` as a single orchestrator class** - the CLI (and later, a
  possible API layer) only ever calls `Scanner.run()`. Internal
  methods can be rewritten stage by stage without breaking callers.
- **`config.py` isolates tunables** - header lists and risk weights
  live in one file so Stage 3 and Stage 5 modify data, not logic.

## Folder structure

```
security-headers-analyzer/
├── src/
│   └── security_headers_analyzer/
│       ├── __init__.py
│       ├── cli.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── models.py
│       │   ├── config.py
│       │   └── scanner.py
│       └── utils/
│           ├── __init__.py
│           └── logger.py
├── tests/
│   ├── __init__.py
│   └── test_models.py
├── docs/
│   └── ARCHITECTURE.md
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
└── pyproject.toml
```

## Stage roadmap (for references)

| Stage | Focus |
|-------|-------|
| 1 | Repository setup + architecture (this stage) |
| 2 | URL validation + HTTP engine |
| 3 | Security header detection |
| 4 | Missing header analysis |
| 5 | Risk scoring system |
| 6 | Report generation |
| 7 | Testing + optimization |
| 8 | Production release |

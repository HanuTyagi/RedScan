# RedScan

Conference-demo-ready RedScan implementation with:

- Smart Scan Module (adaptive discovery + deep enumeration handoff)
- Wrapped Preset Manager with conflict resolution
- Graph-based Command Factory Engine (`networkx`)
- Real-time async runtime parser
- LLM semantic analysis abstraction (mock provider by default)
- FastAPI service layer

## Run

```bash
python -m pip install -r requirements.txt
uvicorn app:app --reload
```

## API

- `GET /health`
- `POST /scan`
- `POST /scan/stream` (NDJSON)

## Tests

```bash
pytest -q
```

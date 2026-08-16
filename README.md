# corroboration-service

Evidence corroboration service for subject `9hcr1e.example`.

## Endpoint

`POST /corroborate`

Request body:
```json
{
  "claim": {"subject": "...", "predicate": "resolves_to", "value": "203.0.113.20"},
  "asOf": "2026-08-01T00:00:00Z",
  "stalenessDays": 180,
  "sources": [
    {"id": "s1", "type": "dns", "origin": "resolver-a",
     "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": false}
  ]
}
```

Response:
```json
{"verdict": "supported", "confidence": "high", "corroboratingSources": ["s1", "s2"]}
```

The service never reads the wall clock — all time math is derived from `asOf`
and `stalenessDays` in the request.

## Deploy on Render

1. Push this repo to GitHub.
2. In Render: **New +** → **Blueprint** → point at the repo (uses `render.yaml`), or **New +** → **Web Service** with:
   - Build Command: `npm install`
   - Start Command: `npm start`
3. Render assigns a URL like `https://corroboration-service.onrender.com`.
4. Test:
```bash
   curl -X POST https://corroboration-service.onrender.com/corroborate \
     -H "Content-Type: application/json" \
     -d @sample-request.json
```

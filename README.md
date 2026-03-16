# VibeServer (Backend Webhook Integration)

A minimal backend server for VibeSecure with webhook endpoints for frontend integration.

## Run

1. `cd vibeserver`
2. `npm install`
3. `npm start`

## Endpoints

- `GET /health` - health check.
- `POST /webhook/vibesecure` - webhook receiver.
  - Required body: `{ eventType, payload }`
  - eventType supported: `session:create`, `stage:update`, `stage:complete`, `lookup:session`
- `GET /api/sessions` - list sessions.
- `GET /api/sessions/:sessionId` - get session detail.

## Example webhook payload

```json
{
  "eventType": "session:create",
  "payload": {
    "sessionId": "session-123",
    "user": "alice",
    "expertiseTier": "beginner"
  }
}
```

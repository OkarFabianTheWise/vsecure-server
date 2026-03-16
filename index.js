const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 4000;

app.use(cors());
app.use(bodyParser.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// In-memory session state (demo). Replace with DB in production.
const sessions = {};

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vibeserver', timestamp: new Date().toISOString() });
});

// Webhook receiver for frontend actions (stage events, user decisions, etc.)
app.post('/webhook/vibesecure', (req, res) => {
  const { eventType, payload } = req.body;

  if (!eventType || !payload) {
    return res.status(400).json({ error: 'eventType and payload are required' });
  }

  switch (eventType) {
    case 'session:create': {
      const { sessionId, user, expertiseTier } = payload;
      if (!sessionId) {
        return res.status(400).json({ error: 'payload.sessionId is required for session:create' });
      }
      sessions[sessionId] = {
        sessionId,
        user: user || 'unknown',
        expertiseTier: expertiseTier || 'intermediate',
        createdAt: new Date().toISOString(),
        stage: 'context',
        history: []
      };
      return res.json({ status: 'created', session: sessions[sessionId] });
    }

    case 'stage:update': {
      const { sessionId, stage, data } = payload;
      if (!sessionId || !stage) {
        return res.status(400).json({ error: 'payload.sessionId and payload.stage are required for stage:update' });
      }
      const session = sessions[sessionId];
      if (!session) {
        return res.status(404).json({ error: 'session not found' });
      }
      session.stage = stage;
      session.updatedAt = new Date().toISOString();
      session.history.push({ type: 'stage:update', stage, data, ts: session.updatedAt });
      return res.json({ status: 'updated', session });
    }

    case 'stage:complete': {
      const { sessionId, stage, results } = payload;
      if (!sessionId || !stage) {
        return res.status(400).json({ error: 'payload.sessionId and payload.stage are required for stage:complete' });
      }
      const session = sessions[sessionId];
      if (!session) {
        return res.status(404).json({ error: 'session not found' });
      }
      const stageRecord = {
        stage,
        results,
        completedAt: new Date().toISOString()
      };
      session.history.push({ type: 'stage:complete', ...stageRecord });
      session.stage = stage;
      return res.json({ status: 'completed', session });
    }

    case 'lookup:session': {
      const { sessionId } = payload;
      if (!sessionId) {
        return res.status(400).json({ error: 'payload.sessionId is required for lookup:session' });
      }
      const session = sessions[sessionId];
      if (!session) {
        return res.status(404).json({ error: 'session not found' });
      }
      return res.json({ status: 'ok', session });
    }

    default:
      return res.status(400).json({ error: `unknown eventType: ${eventType}` });
  }
});

// Basic API for listing sessions and details in demo mode
app.get('/api/sessions', (req, res) => {
  const items = Object.values(sessions);
  res.json({ count: items.length, sessions: items });
});

app.get('/api/sessions/:sessionId', (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) return res.status(404).json({ error: 'session not found' });
  res.json(session);
});

app.listen(port, () => {
  console.log(`VibeServer running on http://localhost:${port}`);
});

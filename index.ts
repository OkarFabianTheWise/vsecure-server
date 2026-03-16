import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';

const app = express();
const port = 3000; // process.env.PORT ? Number(process.env.PORT) : 4000;

app.use(cors());
app.use(bodyParser.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

interface SessionData {
  sessionId: string;
  user: string;
  expertiseTier: string;
  createdAt: string;
  updatedAt?: string;
  stage: string;
  history: Array<Record<string, unknown>>;
}

const sessions: Record<string, SessionData> = {};

function analyzeThreatSurface(context: Record<string, string>): { threat: string; cwe: string; description: string }[] {
  const threats: { threat: string; cwe: string; description: string }[] = [];
  const text = `${context.projectName || ''} ${context.description || ''} ${context.deployment || ''} ${context.compliance || ''}`.toLowerCase();
  if (text.includes('upload') || text.includes('file')) {
    threats.push({ threat: 'Path traversal / unsafe uploads', cwe: 'CWE-22 / CWE-434', description: 'User input in file paths and uploads can expose path traversal and unrestricted upload issues.' });
  }
  if (text.includes('sql') || text.includes('database') || text.includes('query')) {
    threats.push({ threat: 'SQL injection', cwe: 'CWE-89', description: 'Unsanitized inputs in SQL queries can lead to SQL injection.' });
  }
  if (text.includes('token') || text.includes('auth') || text.includes('session')) {
    threats.push({ threat: 'Session management', cwe: 'CWE-384', description: 'Weak session handling may enable fixation or session theft.' });
  }
  if (text.includes('external') || text.includes('http') || text.includes('api')) {
    threats.push({ threat: 'SSRF / hardcoded endpoints', cwe: 'CWE-918', description: 'Untrusted external request URLs can allow SSRF or injection.' });
  }
  if (threats.length === 0) {
    threats.push({ threat: 'Input validation', cwe: 'CWE-20', description: 'General input validation and sanitization should be enforced.' });
  }
  return threats;
}

function analyzeCodeForVulns(code: string) {
  const findings: Array<{ cwe: string; message: string; line: number }> = [];
  const lines = code.split(/\r?\n/);
  lines.forEach((line, idx) => {
    const trimmed = line.trim().toLowerCase();
    if (/eval\(|new Function\(|exec\(|spawn\(|system\(|popen\(/.test(trimmed)) {
      findings.push({ cwe: 'CWE-95', message: 'Potential unsafe dynamic code execution', line: idx + 1 });
    }
    if (/\bselect\b.*\+|\+.*\bfrom\b|prepare\(|execute\(|database\.query\(/.test(trimmed)) {
      findings.push({ cwe: 'CWE-89', message: 'Potential SQL injection pattern detected', line: idx + 1 });
    }
    if (/fs\.(readFile|writeFile|readFileSync|writeFileSync)\(|path\.join\(|path\.resolve\(/.test(trimmed) && /\$\{.*\}|\+\s*req\.|req\./.test(trimmed)) {
      findings.push({ cwe: 'CWE-22', message: 'Potential path traversal with user-controlled data', line: idx + 1 });
    }
  });
  return findings;
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vibeserver', timestamp: new Date().toISOString() });
});

app.post('/webhook/vibesecure', (req, res) => {
  const { eventType, payload } = req.body as { eventType?: string; payload?: any };

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
        user: typeof user === 'string' ? user : 'unknown',
        expertiseTier: typeof expertiseTier === 'string' ? expertiseTier : 'intermediate',
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
      let checks: any = undefined;
      if (stage === 'generation' && results && typeof results.code === 'string') {
        checks = analyzeCodeForVulns(results.code);
      }
      const stageRecord: Record<string, any> = {
        stage,
        results,
        completedAt: new Date().toISOString(),
      };
      if (checks) {
        stageRecord.analysis = checks;
      }
      session.history.push({ type: 'stage:complete', ...stageRecord });
      session.stage = stage;
      return res.json({ status: 'completed', session, checks: checks || [] });
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

    case 'analyze:threat': {
      const { context } = payload;
      if (!context || typeof context !== 'object') {
        return res.status(400).json({ error: 'payload.context object required' });
      }
      const analysis = analyzeThreatSurface(context);
      return res.json({ status: 'ok', analysis });
    }

    case 'analyze:code': {
      const { code } = payload;
      if (!code || typeof code !== 'string') {
        return res.status(400).json({ error: 'payload.code string required' });
      }
      const findings = analyzeCodeForVulns(code);
      return res.json({ status: 'ok', findings });
    }

    default:
      return res.status(400).json({ error: `unknown eventType: ${eventType}` });
  }
});

app.get('/api/sessions', (req, res) => {
  const items = Object.values(sessions);
  res.json({ count: items.length, sessions: items });
});

app.get('/api/sessions/:sessionId', (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) {
    return res.status(404).json({ error: 'session not found' });
  }
  res.json(session);
});

app.listen(port, () => {
  console.log(`VibeServer running on http://localhost:${port}`);
});

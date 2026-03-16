import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import OpenAI from 'openai';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import os from 'os';
import path from 'path';

const execAsync = promisify(exec);

const app = express();
app.use(cors());
app.use(express.json());
const port = 3000;

type Threat = { threat: string; cwe: string; description: string };

type VulnerabilityFinding = { cwe: string; message: string; line: number };

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

const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : undefined;

async function analyzeThreatSurface(context: Record<string, string>): Promise<Threat[]> {
  if (!openai) {
    return [
      { threat: 'Input validation', cwe: 'CWE-20', description: 'Could not run LLM threat analysis due to missing OpenAI API key.' }
    ];
  }

  const prompt = `Given this project context, list the top 3 likely threat vectors and the best mitigation for each (include CWE IDs):\n` +
    `Project name: ${context.projectName || 'N/A'}\n` +
    `Description: ${context.description || 'N/A'}\n` +
    `Language: ${context.language || 'N/A'}\n` +
    `Deployment: ${context.deployment || 'N/A'}\n` +
    `Compliance: ${context.compliance || 'N/A'}\n` +
    `Return JSON array of objects: { threat, cwe, description }.`;

  if (!openai) {
    return [
      { threat: 'Input validation', cwe: 'CWE-20', description: 'OpenAI API key is not configured.' }
    ];
  }

  const completion = await openai.chat.completions.create({
    model: 'gpt-4.1-mini',
    messages: [
      { role: 'system', content: 'You are a secure software architect assistant.' },
      { role: 'user', content: prompt }
    ],
    temperature: 0.2,
    max_tokens: 320,
  });

  const text = completion.choices?.[0]?.message?.content?.trim();
  if (!text) {
    return [
      { threat: 'Input validation', cwe: 'CWE-20', description: 'OpenAI returned no threat analysis.' }
    ];
  }

  try {
    const parsed = JSON.parse(text.replace(/^[^\[]*/, '').replace(/[^\]]*$/, '')) as Threat[];
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed;
    }
  } catch {
    // ignore parse errors and fallback to heuristics
  }

  // Fallback simple heuristics
  const textLower = `${context.projectName || ''} ${context.description || ''} ${context.deployment || ''} ${context.compliance || ''}`.toLowerCase();
  const threats: Threat[] = [];
  if (textLower.includes('upload') || textLower.includes('file')) {
    threats.push({ threat: 'Path traversal / unsafe uploads', cwe: 'CWE-22 / CWE-434', description: 'User input in file paths and uploads can expose path traversal vulnerabilities.' });
  }
  if (textLower.includes('sql') || textLower.includes('database') || textLower.includes('query')) {
    threats.push({ threat: 'SQL injection', cwe: 'CWE-89', description: 'Unsanitized SQL query usage may allow injection.' });
  }
  if (textLower.includes('token') || textLower.includes('auth') || textLower.includes('session')) {
    threats.push({ threat: 'Session management', cwe: 'CWE-384', description: 'Weak session handling may lead to session hijacking.' });
  }
  if (threats.length === 0) {
    threats.push({ threat: 'Input validation', cwe: 'CWE-20', description: 'General input validation and sanitization should be enforced.' });
  }
  return threats;
}

async function generateSecureCode(context: Record<string, string>, snippet: string, threats: string[]): Promise<string> {
  if (!openai) {
    return `// Unable to generate secure code because OpenAI API key is not configured.\n// Use the provided snippet as the base code and apply secure controls.`;
  }

  const prompt = `You are a secure software architect assistant. Given the project context and identified threats, generate secure TypeScript code implementing this service. Include inline security comments with CWE references and uncertainty flags where needed.\n\nContext: ${JSON.stringify(context)}\nThreats: ${JSON.stringify(threats)}\nUser snippet:\n${snippet}\n`;

  const completion = await openai.chat.completions.create({
    model: 'gpt-4.1-mini',
    messages: [
      { role: 'system', content: 'You are a secure code generation assistant.' },
      { role: 'user', content: prompt }
    ],
    temperature: 0.2,
    max_tokens: 700,
  });

  const text = completion.choices?.[0]?.message?.content?.trim();
  return text || `// Could not generate secure code from LLM. Use the user snippet as code output.`;
}

async function analyzeCodeForVulns(code: string): Promise<VulnerabilityFinding[]> {
  const findings: VulnerabilityFinding[] = [];

  // Basic regex detector
  const lines = code.split(/\r?\n/);
  for (let idx = 0; idx < lines.length; idx += 1) {
    const trimmed = lines[idx].trim().toLowerCase();
    if (/eval\(|new Function\(|exec\(|spawn\(|system\(|popen\(/.test(trimmed)) {
      findings.push({ cwe: 'CWE-95', message: 'Potential dynamic code execution', line: idx + 1 });
    }
    if ((/\b(select|insert|update|delete)\b/.test(trimmed) && /\+/.test(trimmed)) || /prepare\(|execute\(|database\.query\(/.test(trimmed)) {
      findings.push({ cwe: 'CWE-89', message: 'Potential SQL injection pattern (dynamic SQL/DB execution)', line: idx + 1 });
    }
    if (/fs\.(readFile|writeFile|readFileSync|writeFileSync)\(|path\.join\(|path\.resolve\(/.test(trimmed) && /\$\{.*\}|\+\s*req\.|req\./.test(trimmed)) {
      findings.push({ cwe: 'CWE-22', message: 'Potential path traversal with user-controlled data', line: idx + 1 });
    }
  }

  // Optional semgrep run
  try {
    const tmpFile = path.join(os.tmpdir(), `vibesecure-code-${Date.now()}.js`);
    fs.writeFileSync(tmpFile, code, "utf8");
    const semgrepCmd = `semgrep --config=c2 --json --output - ${tmpFile}`;
    const { stdout } = await execAsync(semgrepCmd, { timeout: 120000 });
    const json = JSON.parse(stdout);
    if (Array.isArray(json.results)) {
      json.results.forEach((r: any) => {
        findings.push({
          cwe: r.extra?.metadata?.cwe || 'CWE-0',
          message: r.extra?.message || `${r.check_id}: ${r.extra?.short_description || 'Semgrep finding'}`,
          line: r.start?.line || 0,
        });
      });
    }
    fs.unlinkSync(tmpFile);
  } catch (err) {
    // semgrep not available or failed; keep regex results
  }

  return findings;
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vibeserver', timestamp: new Date().toISOString() });
});

app.post('/webhook/vibesecure', async (req, res) => {
  const { eventType, payload } = req.body as { eventType?: string; payload?: any };
  // console.log('[webhook] eventType=', eventType, 'payload=', payload && (typeof payload === 'object' ? JSON.stringify(payload) : payload));

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
        checks = await analyzeCodeForVulns(results.code);
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
      // console.log('[webhook] analyze:threat context:', context);
      const analysis = await analyzeThreatSurface(context);
      // console.log('[webhook] analyze:threat result:', analysis);
      return res.json({ status: 'ok', analysis });
    }

    case 'analyze:code': {
      const { code } = payload;
      if (!code || typeof code !== 'string') {
        return res.status(400).json({ error: 'payload.code string required' });
      }
      // console.log('[webhook] analyze:code snippet length:', code.length);
      const findings = await analyzeCodeForVulns(code);
      // console.log('[webhook] analyze:code findings:', findings);
      return res.json({ status: 'ok', findings });
    }

    case 'generate:secure-code': {
      const { context, snippet, threats } = payload;
      if (!context || typeof context !== 'object') {
        return res.status(400).json({ error: 'payload.context object required' });
      }
      if (!snippet || typeof snippet !== 'string') {
        return res.status(400).json({ error: 'payload.snippet string required' });
      }
      const code = await generateSecureCode(context, snippet, Array.isArray(threats) ? threats.map(String) : []);
      return res.json({ status: 'ok', code });
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

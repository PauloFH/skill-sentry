const WEIGHT = { critical: 40, high: 15, medium: 5, info: 0 };
const ESCALATES_OBF = new Set(['rce', 'exfil', 'secret']);
// A credential stored in config is not code that reads secrets: it never feeds the combination
// escalations (secret + exfil -> critical, obfuscation + secret -> high). Ruling R10.
const NO_COMBINATION = new Set(['CODEX_SECRET_IN_CONFIG']);

/**
 * Turn findings into a score and verdict, applying per-file combination escalation.
 * Score = sum over distinct rule ids of the highest severity weight seen for that rule.
 * Input findings are not mutated; escalated findings are copies with `escalated: true`.
 * @param {Array<import('./scanner.mjs').Finding>} findings
 * @returns {{ score: number, verdict: 'ok'|'review'|'suspicious'|'malicious', findings: Array }}
 */
export function scoreComponent(findings) {
  const catsByFile = new Map();
  for (const f of findings) {
    if (!catsByFile.has(f.file)) catsByFile.set(f.file, new Set());
    if (!NO_COMBINATION.has(f.ruleId)) catsByFile.get(f.file).add(f.category);
  }
  const out = findings.map(f => {
    const cats = catsByFile.get(f.file);
    if (f.category === 'exfil' && cats.has('secret') && f.severity !== 'critical') {
      return { ...f, severity: 'critical', escalated: true };
    }
    if (f.category === 'obfuscation' && [...cats].some(c => ESCALATES_OBF.has(c))
        && (f.severity === 'medium' || f.severity === 'info')) {
      return { ...f, severity: 'high', escalated: true };
    }
    return f;
  });
  // Each rule counts once, at its highest (post-escalation) severity: repeating one pattern in many
  // files adds little evidence, while distinct rules do. Every finding is still reported.
  const best = new Map();
  for (const f of out) best.set(f.ruleId, Math.max(best.get(f.ruleId) ?? 0, WEIGHT[f.severity] ?? 0));
  const score = Math.min(100, [...best.values()].reduce((n, w) => n + w, 0));
  let verdict = score < 10 ? 'ok' : score < 30 ? 'review' : score < 60 ? 'suspicious' : 'malicious';
  if (verdict === 'ok' || verdict === 'review') {
    if (out.some(f => f.severity === 'critical')) verdict = 'suspicious';
  }
  return { score, verdict, findings: out };
}

// Content check behind the guard's standalone exemption (final review I1): a command naming a standalone
// skill-sentry install (`npx skills add`) is exempt from SELF_PROTECT only when that dir is a verified copy of the
// running skill (selfcopy.mjs matchSelf 'skill': same bytes as the running skill dir, the running self-manifest's
// skills/audit subset, or a recorded release). selfcopy.mjs (and its release table) is imported only when the
// command already has that shape, so the guard's none path pays nothing; the whole check is capped (Ruling L1:
// bounded work before the decision) and any doubt, error or timeout means "not verified".
import path from 'node:path';
import { mayNameStandaloneSelf } from './guardcore.mjs';

/** Budget for the import and every copy check of one decision, in ms. */
export const VERIFY_BUDGET_MS = 200;

/**
 * A sync `verifySkill(dir) -> boolean` for decide(), or null when `command` cannot name a standalone copy (or the
 * check cannot be loaded). Results are memoised per dir; past the budget (or `deadline`) every dir is unverified.
 */
export async function standaloneVerifier(command, selfRoot, { deadline = Infinity, budgetMs = VERIFY_BUDGET_MS, now = Date.now } = {}) {
  if (!mayNameStandaloneSelf(command) || typeof selfRoot !== 'string' || !selfRoot) return null;
  const until = Math.min(deadline, now() + budgetMs);
  let matchSelf;
  try {
    ({ matchSelf } = await import('./selfcopy.mjs'));
  } catch {
    return null;
  }
  const memo = new Map();
  return dir => {
    const key = path.resolve(String(dir));
    if (!memo.has(key)) {
      let ok = false;
      try {
        ok = now() < until && matchSelf(key, 'skill', { selfRoot, deadline: until }).self === true && now() <= until;
      } catch {
        ok = false;
      }
      memo.set(key, ok);
    }
    return memo.get(key);
  };
}

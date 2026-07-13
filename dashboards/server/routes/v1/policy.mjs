import { access, readFile, writeFile, unlink, mkdir } from 'node:fs/promises';
import { join }   from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { genseeHome } from '../../db.mjs';

const execFileAsync = promisify(execFile);

const policyPath   = join(genseeHome, 'policy.json');
const defaultPolicyPath = new URL(
  '../../../../crate/gensee-crate-rules/policy/default-policy.json',
  import.meta.url,
).pathname;

// Candidate gensee binaries for validation.
function genseeCandidates() {
  // policy.mjs lives at ui/server/routes/v1/ — four levels up reaches the repo root.
  const repoRoot = new URL('../../../../', import.meta.url).pathname;
  return [
    process.env.GENSEE_BIN,
    join(repoRoot, 'target', 'release', 'gensee'),
    join(repoRoot, 'target', 'debug',   'gensee'),
    'gensee',
  ].filter(Boolean);
}

/**
 * GET /api/v1/policy  — return the policy document as JSON.
 * POST /api/v1/policy — validate and overwrite the policy document.
 */
export async function handlePolicy(method, body = null) {
  if (method === 'get') {
    // Try the user's customised policy first; fall back to the bundled default.
    for (const path of [policyPath, defaultPolicyPath]) {
      try {
        const text = await readFile(path, 'utf8');
        return JSON.parse(text);
      } catch { /* try next */ }
    }
    return null; // no policy found at all
  }

  if (method === 'set') {
    if (!body || typeof body !== 'object') {
      throw new Error('Request body must be a JSON object.');
    }

    const text = JSON.stringify(body, null, 2) + '\n';

    // Best-effort validation via gensee binary.
    const tmpPath = join(genseeHome, `.policy-validate-${randomUUID()}.json`);
      let validated = false;
      try {
        await mkdir(genseeHome, { recursive: true });
        await writeFile(tmpPath, text, 'utf8');

        for (const bin of genseeCandidates()) {
          try {
            await execFileAsync(bin, ['policy', 'validate', tmpPath], {
              maxBuffer: 1024 * 1024,
              env: { ...process.env, GENSEE_HOME: genseeHome },
            });
            validated = true;
            break; // validated successfully
          } catch (err) {
            if (err.code !== 'ENOENT') {
              // A real validation failure from the binary.
              const detail = (err.stderr ?? err.message ?? '').toString().trim();
              throw new Error(`Policy validation failed: ${detail}`);
            }
            // Binary not found at this path — try the next candidate.
          }
        }
      } finally {
        await unlink(tmpPath).catch(() => {});
      }

      if (!validated) {
        throw new Error(
          'No gensee binary found for policy validation. ' +
          'Build the CLI first: cargo build --release -p gensee-crate-cli, ' +
          'or set GENSEE_BIN to the binary path.'
        );
      }

    await mkdir(genseeHome, { recursive: true });
    await writeFile(policyPath, text, 'utf8');
    return { ok: true };
  }

  throw new Error(`Unknown policy method: ${method}`);
}

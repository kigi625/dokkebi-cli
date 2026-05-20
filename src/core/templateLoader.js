/**
 * Template loader for worker/admin/etc. files extracted from former inline strings.
 *
 * Templates live under `src/templates/<group>/<name>.<ext>.tpl` and use placeholder
 * tokens that we replace at generation time:
 *
 *   "__DOKKEBI_PLACEHOLDER_SUMMARY__"  →  JSON.stringify(securitySummary)
 *   __DOKKEBI_PLACEHOLDER_PROJECT__    →  projectName
 *
 * For booleans (e.g. `_PANEL_IP_GUARD_ENABLED = false;`) we use a literal-line
 * replace so the .tpl file stays valid TypeScript that an editor can lint.
 */

import fs from 'fs';
import path from 'path';
import url from 'url';

const __filename = url.fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), '..');

/** @type {Map<string, string>} */
const _cache = new Map();

/** @param {string} relPath e.g. 'worker/handshake.ts.tpl' */
function loadTemplate(relPath) {
    const cached = _cache.get(relPath);
    if (cached !== undefined) return cached;
    const abs = path.join(ROOT, 'templates', relPath);
    const text = fs.readFileSync(abs, 'utf-8');
    _cache.set(relPath, text);
    return text;
}

/**
 * Apply replacements safely. Each replacement has a `find` (string or regex) and a `replace`.
 * Throws if `find` doesn't match — keeps templates honest.
 *
 * @param {string} relPath
 * @param {Array<{ find: string | RegExp, replace: string, optional?: boolean }>} replacements
 * @returns {string}
 */
export function renderTemplate(relPath, replacements) {
    let out = loadTemplate(relPath);
    for (const r of replacements) {
        if (r.find instanceof RegExp) {
            if (!r.optional && !r.find.test(out)) {
                throw new Error(`renderTemplate(${relPath}): pattern ${r.find} not found`);
            }
            out = out.replace(r.find, r.replace);
        } else {
            const idx = out.indexOf(r.find);
            if (idx === -1) {
                if (r.optional) continue;
                throw new Error(`renderTemplate(${relPath}): literal ${JSON.stringify(r.find.slice(0, 60))} not found`);
            }
            out = out.split(r.find).join(r.replace);
        }
    }
    return out;
}

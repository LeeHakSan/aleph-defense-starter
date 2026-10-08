import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const FIXTURE = join(ROOT, 'xdr', 'fixtures', 'brute-force.json');

export { mask, extractAlert } from './alert-fields.mjs';
import { extractAlert } from './alert-fields.mjs';

export async function readAlerts(path = FIXTURE) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (!Array.isArray(fixture?.alerts)) throw new Error('경보 묶음 형식이 아닙니다.');
  return { total: fixture.alerts.length, rows: fixture.alerts.map(extractAlert) };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const { total, rows } = await readAlerts();
  for (const row of rows) console.log(JSON.stringify(row));
  console.log(`경보 ${total}건 · 뽑은 줄 ${rows.length}줄 · ${total === rows.length ? '일치' : '불일치'}`);
}

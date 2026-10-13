import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

// 12단계: npm run bundle 이 실제 배포에 보낸 요청의 결과(artifacts/submission.json)를 한 표로 출력합니다.
// 결과를 고치거나 채우지 않고 그대로 옮기며, 보내지 못한 점검은 미실행으로 남습니다.
// --write 를 붙이면 README.md 의 표시(checks-table) 사이를 이 표로 바꿔 씁니다.
const root = resolve(import.meta.dirname, '..');
const bundle = JSON.parse(readFileSync(join(root, 'artifacts', 'submission.json'), 'utf8'));
const label = { blocked: '막음(기대대로)', breached: '뚫림', not_run: '미실행' };
const cell = (value) => String(value).replaceAll('|', '\\|');
const count = (result) => bundle.attackAttempts.filter((item) => item.result === result).length;

const lines = [
  `점검 시각 ${bundle.checkedAt ?? '-'} · 커밋 ${String(bundle.commit).slice(0, 12)} · 단계 ${bundle.step}`,
  '',
  '| 단계 | 점검 | 기대 | 실제 응답(observed) | 결과 |',
  '|---|---|---|---|---|',
  ...bundle.attackAttempts.map((a) => `| ${a.stage} | ${cell(a.attackId)} | ${cell(a.expected)} | ${cell(a.observed)} | ${label[a.result] ?? a.result} |`),
  '',
  `막음 ${count('blocked')} · 뚫림 ${count('breached')} · 미실행 ${count('not_run')}`,
];
const table = `${lines.join('\n')}\n`;

if (process.argv.includes('--write')) {
  const path = join(root, 'README.md');
  const readme = readFileSync(path, 'utf8');
  const start = '<!-- checks-table:start -->';
  const end = '<!-- checks-table:end -->';
  const from = readme.indexOf(start);
  const to = readme.indexOf(end);
  if (from < 0 || to < from) throw new Error('README.md 에 checks-table 표시가 없습니다.');
  writeFileSync(path, `${readme.slice(0, from + start.length)}\n\n${table}\n${readme.slice(to)}`, 'utf8');
  process.stdout.write('README.md 의 실측 결과 표를 바꿨습니다.\n');
} else {
  process.stdout.write(table);
}

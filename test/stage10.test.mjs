import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';
import { RULE_IDS } from '../src/decider.mjs';
import {
  applyPolicyRestore, canonicalJson, planPolicyRestore, PolicyRecoveryError, SAFE_POLICY_SHA256, verifySafeCopy,
} from '../src/policy-recovery.mjs';
import { loadRecoveryPlan, readVerifiedCopy } from '../src/policy-files.mjs';
import { run as runPolicyCli } from '../scripts/policy-recovery.mjs';
import { restoreNote } from '../src/restore.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const copyText = await readFile(new URL('../backups/safe-policy.json', import.meta.url), 'utf8');
const healthyText = await readFile(new URL('../policy/test-policy.json', import.meta.url), 'utf8');
const verified = verifySafeCopy(copyText);
const healthy = () => JSON.parse(healthyText);
const breached = () => {
  const policy = healthy();
  policy.version = 4;
  policy.services.notes.readRoutes.push('PUT /api/notes/:id', 'GET /api/notes');
  policy.services.notes.engineWrites = 'allow';
  policy.services.notes.ruleIds = policy.services.notes.ruleIds.filter(id => id !== 'write_not_allowed');
  policy.services.detect.limit = 100000;
  policy.auditLog.push({ at: '2026-10-12T00:00:00.000Z', action: 'earlier_event' });
  return policy;
};
const throwsCode = (fn, code) => assert.throws(fn, error => error instanceof PolicyRecoveryError && error.code === code);

test('정책 사본: 프로젝트·버전·고정 SHA-256 이 맞을 때만 검증되고, 아니면 중단', () => {
  assert.equal(verified.version, 1);
  assert.match(SAFE_POLICY_SHA256, /^[0-9a-f]{64}$/u);
  throwsCode(() => verifySafeCopy(undefined), 'policy_copy_missing');
  throwsCode(() => verifySafeCopy('   '), 'policy_copy_missing');
  throwsCode(() => verifySafeCopy('{not json'), 'policy_copy_unverified');
  const mutate = change => { const copy = JSON.parse(copyText); change(copy); return JSON.stringify(copy); };
  throwsCode(() => verifySafeCopy(mutate(copy => { copy.services.notes.engineWrites = 'allow'; })), 'policy_copy_unverified');
  throwsCode(() => verifySafeCopy(mutate(copy => { copy.services.notes.readRoutes.push('PUT /api/notes/:id'); })), 'policy_copy_unverified');
  throwsCode(() => verifySafeCopy(mutate(copy => { copy.project = 'someone-else'; })), 'policy_copy_unverified');
  throwsCode(() => verifySafeCopy(mutate(copy => { copy.version = 2; })), 'policy_copy_unverified');
  throwsCode(() => verifySafeCopy(mutate(copy => { delete copy.services.notes; })), 'policy_copy_unverified');
  assert.doesNotThrow(() => verifySafeCopy(JSON.stringify(JSON.parse(copyText), null, 8)));
});

test('시험 정책은 실제 정책(RULE_IDS·허용 경로)과 같아서 정상 상태의 차이는 0건', () => {
  const notes = healthy().services.notes;
  assert.deepEqual(notes.ruleIds, [...RULE_IDS]);
  assert.deepEqual(notes.readRoutes, config.allowedRoutes);
  const plan = planPolicyRestore(verified, healthy());
  assert.deepEqual(plan.changes, []);
  assert.equal(plan.confirmation, null);
});

test('계획: 침해된 시험 정책과의 차이만 칸 단위로 보여 주고 다른 서비스·감사 이력은 보존 목록에 올린다', () => {
  const plan = planPolicyRestore(verified, breached());
  assert.equal(plan.restoreVersion, 1);
  assert.equal(plan.currentVersion, 4);
  assert.deepEqual(plan.changes.map(change => change.field), ['engineWrites', 'readRoutes', 'ruleIds']);
  assert.ok(plan.changes.every(change => change.service === 'notes'));
  assert.deepEqual(plan.preservedServices, ['detect']);
  assert.equal(plan.preservedAuditEntries, 1);
  assert.match(plan.confirmation, /^[0-9a-f]{64}$/u);
  assert.equal(plan.confirmation, planPolicyRestore(verified, breached()).confirmation);
});

test('적용: 확인값이 맞을 때만 notes 정책을 되돌리고 다른 서비스·감사 이력은 그대로, 입력은 바뀌지 않는다', () => {
  const current = breached();
  const before = canonicalJson(current);
  const { confirmation } = planPolicyRestore(verified, current);
  const next = applyPolicyRestore(verified, current, confirmation, { at: '2026-10-13T00:00:00.000Z' });
  assert.equal(canonicalJson(current), before);
  assert.deepEqual(next.services.notes, verified.services.notes);
  assert.deepEqual(next.services.detect, current.services.detect);
  assert.equal(next.version, 5);
  assert.equal(next.auditLog.length, 2);
  assert.deepEqual(next.auditLog[0], current.auditLog[0]);
  assert.equal(next.auditLog[1].action, 'restore_policy');
  assert.equal(next.auditLog[1].restoredFromVersion, 1);
  assert.deepEqual(planPolicyRestore(verified, next).changes, []);
  next.services.notes.readRoutes.push('x');
  assert.equal(verified.services.notes.readRoutes.includes('x'), false);
});

test('적용 거부: 확인값이 없거나 다르거나 바꿀 것이 없으면 아무것도 쓰지 않는다', () => {
  const current = breached();
  throwsCode(() => applyPolicyRestore(verified, current), 'confirmation_mismatch');
  throwsCode(() => applyPolicyRestore(verified, current, 'abc'), 'confirmation_mismatch');
  throwsCode(() => applyPolicyRestore(verified, current, planPolicyRestore(verified, current).confirmation.replace(/^./u, 'x')), 'confirmation_mismatch');
  throwsCode(() => applyPolicyRestore(verified, healthy(), null), 'nothing_to_restore');
  const other = breached();
  other.services.notes.engineWrites = 'allow-more';
  throwsCode(() => applyPolicyRestore(verified, other, planPolicyRestore(verified, current).confirmation), 'confirmation_mismatch');
  throwsCode(() => planPolicyRestore(verified, { ...healthy(), auditLog: undefined }), 'test_policy_invalid');
  throwsCode(() => planPolicyRestore(verified, null), 'test_policy_invalid');
});

test('파일 읽기: 사본을 호출할 때마다 다시 읽어 검증하고, 없거나 고쳐졌으면 중단한다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'stage10-'));
  try {
    const copyUrl = pathToFileURL(join(dir, 'safe-policy.json'));
    const policyUrl = pathToFileURL(join(dir, 'test-policy.json'));
    await assert.rejects(readVerifiedCopy(copyUrl), error => error.code === 'policy_copy_missing');
    await writeFile(copyUrl, copyText);
    await writeFile(policyUrl, JSON.stringify(breached()));
    assert.equal((await loadRecoveryPlan({ copyUrl, policyUrl })).plan.changes.length, 3);
    await writeFile(copyUrl, copyText.replace('"deny"', '"allow"'));
    await assert.rejects(loadRecoveryPlan({ copyUrl, policyUrl }), error => error.code === 'policy_copy_unverified');
    await writeFile(copyUrl, copyText);
    assert.equal((await loadRecoveryPlan({ copyUrl, policyUrl })).plan.restoreVersion, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('절차(CLI): plan 은 쓰지 않고, 확인값이 맞을 때만 restore 가 시험 정책 파일을 되돌린다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'stage10-'));
  const lines = [];
  const write = text => lines.push(text);
  try {
    const copyUrl = pathToFileURL(join(dir, 'safe-policy.json'));
    const policyUrl = pathToFileURL(join(dir, 'test-policy.json'));
    await writeFile(copyUrl, copyText);
    const broken = JSON.stringify(breached(), null, 2);
    await writeFile(policyUrl, broken);

    assert.equal(await runPolicyCli(['plan'], { write, policyUrl, copyUrl }), 0);
    assert.equal(await readFile(policyUrl, 'utf8'), broken);
    const confirmation = lines.join('\n').match(/확인값: ([0-9a-f]{64})/u)[1];
    assert.match(lines.join('\n'), /바뀔 항목 3개/u);
    assert.match(lines.join('\n'), /복원할 버전 1/u);

    assert.equal(await runPolicyCli(['restore', 'wrong'], { write, policyUrl, copyUrl }), 1);
    assert.equal(await readFile(policyUrl, 'utf8'), broken);
    assert.equal(await runPolicyCli(['restore'], { write, policyUrl, copyUrl }), 1);
    assert.equal(await readFile(policyUrl, 'utf8'), broken);

    assert.equal(await runPolicyCli(['restore', confirmation], { write, policyUrl, copyUrl }), 0);
    const restored = JSON.parse(await readFile(policyUrl, 'utf8'));
    assert.deepEqual(restored.services.notes, verified.services.notes);
    assert.equal(restored.services.detect.limit, 100000);
    assert.equal(restored.auditLog.length, 2);

    assert.equal(await runPolicyCli(['restore', confirmation], { write, policyUrl, copyUrl }), 1);
    await writeFile(copyUrl, '{}');
    await writeFile(policyUrl, broken);
    assert.equal(await runPolicyCli(['restore', confirmation], { write, policyUrl, copyUrl }), 1);
    assert.equal(await readFile(policyUrl, 'utf8'), broken);
    assert.equal(await runPolicyCli([], { write, policyUrl, copyUrl }), 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- 메모 한 건 복구 API (DB 함수 vault_restore_note 는 가짜로 대신한다) ----
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const NOTE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function fakeRpc(result, { error = null } = {}) {
  const calls = [];
  return { calls, db: { rpc: async (name, args) => { calls.push({ name, args }); return { data: result, error }; } } };
}
function fakeResponse() {
  return {
    headers: {}, code: null, body: null,
    setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
  };
}
const call = async (session, request) => {
  const response = fakeResponse();
  await restoreNote(session, request, response);
  return response;
};

test('복구 API: 소유자는 검증된 로그인에서만 얻고 본문·헤더·쿼리의 소유자·본문·해시는 DB 로 보내지 않는다', async () => {
  const { db, calls } = fakeRpc({ status: 'restored', action: 'updated', id: NOTE, ownerId: B, contentSha256: 'a'.repeat(64) });
  const response = await call({ userId: B, db }, {
    query: { noteId: NOTE, owner_id: A, userId: A }, headers: { 'x-user-id': A },
    body: { owner_id: A, ownerId: A, userId: A, role: 'instructor', content: '위조 본문', contentSha256: 'f'.repeat(64), title: '위조' },
  });
  assert.equal(response.code, 200);
  assert.deepEqual(response.body, { restored: true, action: 'updated', id: NOTE, ownerId: B, contentSha256: 'a'.repeat(64) });
  assert.equal(response.headers['x-resource-id'], `note:${NOTE}`);
  assert.deepEqual(calls, [{ name: 'vault_restore_note', args: { p_note_id: NOTE, p_user_id: B } }]);
});

test('복구 API: DB 결과별 응답(삭제 뒤 복구, 사본 없음, 타인, 사본 검증 실패, 오류)', async () => {
  const cases = [
    [{ status: 'restored', action: 'inserted', id: NOTE, ownerId: B, contentSha256: 'c'.repeat(64) }, 200],
    [{ status: 'restored', action: 'unchanged', id: NOTE, ownerId: B, contentSha256: 'c'.repeat(64) }, 200],
    [{ status: 'no_backup' }, 404],
    [{ status: 'forbidden' }, 403],
    [{ status: 'owner_conflict' }, 403],
    [{ status: 'backup_unverified' }, 409],
    [{ status: '???' }, 502],
    [null, 502],
  ];
  for (const [result, code] of cases) {
    const { db } = fakeRpc(result);
    const response = await call({ userId: B, db }, { query: { noteId: NOTE } });
    assert.equal(response.code, code, JSON.stringify(result));
    if (code !== 200) assert.equal(Object.hasOwn(response.body, 'contentSha256'), false);
  }
  const failing = fakeRpc(null, { error: { code: 'X' } });
  assert.equal((await call({ userId: B, db: failing.db }, { query: { noteId: NOTE } })).code, 502);
  assert.deepEqual((await call({ userId: B, db: fakeRpc({ status: 'forbidden' }).db }, { query: { noteId: NOTE } })).body,
    { error: 'FORBIDDEN', reason: 'not_owner' });
});

test('복구 API: 형식이 틀린 id 는 DB 를 부르지 않고 400', async () => {
  for (const noteId of [undefined, '', 'export', '../x', 'demo', `${NOTE}/x`, 42, [NOTE]]) {
    const { db, calls } = fakeRpc({ status: 'restored' });
    const response = await call({ userId: B, db }, { query: { noteId } });
    assert.equal(response.code, 400, String(noteId));
    assert.equal(calls.length, 0);
  }
});

test('복구 경로가 설정에 있고 README 에 서비스와 함께 적혀 있다', async () => {
  assert.equal(config.restoreRoute, '/api/restore/:noteId');
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
  assert.match(readme, /서비스 notes의 복구 경로는 POST \/api\/restore\/:noteId입니다/u);
  assert.equal(config.allowedRoutes.includes('POST /api/restore/:noteId'), false);
});

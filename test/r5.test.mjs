import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('build identity lists the allowed routes from the config', () => {
  const routes = ['GET /api/notes', 'POST /api/notes', 'GET /api/notes/:id', 'POST /api/auth/login'];
  assert.deepEqual(deploymentIdentity(env, { ...config, allowedRoutes: routes }).allowedRoutes, routes);
  assert.equal('allowedRoutes' in deploymentIdentity(env, config), false);
  assert.equal('allowedRoutes' in deploymentIdentity(env, { ...config, allowedRoutes: [] }), false);
  assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes: ['not a route'] }));
  assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes: 'GET /api/notes' }));
});

test('build identity publishes the original api url only as a plain https path', () => {
  const url = 'https://project.supabase.co/rest/v1/notes';
  assert.equal(deploymentIdentity(env, { ...config, originalApiUrl: url }).originalApiUrl, url);
  assert.equal('originalApiUrl' in deploymentIdentity(env, config), false);
  assert.equal('originalApiUrl' in deploymentIdentity(env, { ...config, originalApiUrl: null }), false);
  for (const bad of ['http://project.supabase.co/rest/v1/notes', `${url}?select=*`, `${url}?`, `${url}#x`,
    'https://user:pw@project.supabase.co/rest/v1/notes', 'https://localhost/rest/v1/notes', 'not a url', '', 5]) {
    assert.throws(() => deploymentIdentity(env, { ...config, originalApiUrl: bad }), undefined, String(bad));
  }
});

const realStep = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8')).step;

test('attack checks call the deployed app without credentials and flag an unprotected one', async () => {
  const stepConfig = {
    ...config,
    step: realStep,
    identityProvider: {
      issuer: 'https://project.supabase.co/auth/v1',
      jwksUrl: 'https://project.supabase.co/auth/v1/.well-known/jwks.json',
      audience: 'authenticated',
    },
  };
  const originalFetch = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const exposed = await runAttackChecks(stepConfig);
    assert.ok(exposed.length >= 1 && exposed.length <= 20);
    assert.equal(exposed[0].attackId, 'data_json_notes_empty');
    assert.match(exposed[0].observed, /메모 또는 확인 표시가 남아 있음/u);
    const dataCall = calls.find(call => call.url === 'https://student-defense.vercel.app/data.json');
    assert.ok(dataCall);
    assert.equal(dataCall.init.redirect, 'error');
    assert.equal(dataCall.init.headers.authorization, undefined);
    assert.match(exposed.find(item => item.attackId === 'api_notes_list_no_token').observed, /거부되지 않음/u);
    assert.match(exposed.find(item => item.attackId === 'api_notices_no_token').observed, /거부되지 않음/u);

    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 401 });
    const closed = await runAttackChecks(stepConfig);
    assert.match(closed[0].observed, /메모·확인 표시 없음/u);
    assert.match(closed.find(item => item.attackId === 'api_notices_no_token').observed, /자료 없이 거부됨/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

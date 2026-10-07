const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;
const ROUTE = /^(GET|POST|PUT|PATCH|DELETE) \/[A-Za-z0-9/_:.-]{0,200}$/u;

// 쿼리·조각·계정 정보가 없는 https 경로만 공개한다. 비밀값이 섞일 길을 막기 위해서다.
function validOriginalApiUrl(value) {
  if (typeof value !== 'string' || value.length > 300 || /[?#\s]/u.test(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && url.hostname.includes('.');
  } catch {
    return false;
  }
}

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;
  const routes = config?.allowedRoutes ?? [];
  const original = config?.originalApiUrl ?? null;
  if (original !== null && !validOriginalApiUrl(original)) {
    throw new Error('aleph.config.json의 originalApiUrl은 쿼리 없는 https 경로여야 합니다.');
  }
  if (!Array.isArray(routes) || routes.length > 50
      || routes.some((route) => typeof route !== 'string' || !ROUTE.test(route))
      || env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '')
      || !Number.isInteger(config?.step) || config.step < 1 || config.step > 12
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || typeof config.sampleMarker !== 'string'
      || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 1단계 시작 틀을 확인하세요.');
  }
  return {
    schema: 'aleph.defense.deployment.v1',
    step: config.step,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    ...(routes.length ? { allowedRoutes: [...routes] } : {}),
    ...(original ? { originalApiUrl: original } : {}),
  };
}

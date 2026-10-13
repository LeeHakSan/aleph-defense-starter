// 배포에 공개하는 설정 사본(/aleph.config.json). 비밀값이 없는 항목만 담고, aleph.config.json 의 값에서 만든다.
// allowedRoutes 는 {service, method, pathPattern, zone} 객체로 바꿔 싣는다(원본의 "GET /api/notes/:id" 문자열 모양을 풀어 쓴 것).
const ZONES = [['/api/my/notes', 'my-notes'], ['/notes/', 'my-notes'], ['/api/notes/', 'my-notes'], ['/api/notices', 'class-notices']];

function routeObject(route) {
  const match = /^(GET|POST|PUT|PATCH|DELETE) (\/\S*)$/u.exec(route);
  if (!match) throw new Error('aleph.config.json의 allowedRoutes 모양을 확인하세요.');
  const [, method, pathPattern] = match;
  const zone = ZONES.find(([prefix]) => pathPattern.startsWith(prefix))?.[1] ?? 'other';
  return { service: pathPattern.includes('/notices') ? 'notices' : 'notes', method, pathPattern, zone };
}

export function publicConfig(config) {
  const routes = Array.isArray(config?.allowedRoutes) ? config.allowedRoutes : [];
  return {
    schema: 'aleph.config.v1',
    step: config.step,
    repoUrl: config.repoUrl,
    ...(typeof config.originalApiUrl === 'string' ? { originalApiUrl: config.originalApiUrl } : {}),
    ...(typeof config.restoreRoute === 'string' ? { restoreRoute: config.restoreRoute } : {}),
    allowedRoutes: routes.map(routeObject),
  };
}

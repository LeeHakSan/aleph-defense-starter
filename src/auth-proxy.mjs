// 브라우저 대신 서버가 Supabase Auth를 부른다. 공개 키는 화면 코드가 아니라 서버 설정(SUPABASE_PUBLISHABLE_KEY)에만 둔다.
export function authSettings() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_PUBLISHABLE_KEY;
  return url && key ? { url: url.replace(/\/+$/u, ''), key } : null;
}

export async function callAuth(settings, path, { body, bearer } = {}) {
  try {
    const response = await fetch(`${settings.url}/auth/v1${path}`, {
      method: 'POST',
      signal: AbortSignal.timeout(8000),
      headers: {
        apikey: settings.key,
        'Content-Type': 'application/json',
        ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await response.json().catch(() => null);
    return { status: response.status, json };
  } catch {
    return { status: 0, json: null };
  }
}

// 브라우저에는 화면에 필요한 값만 돌려준다.
export function publicSession(json) {
  const expiresAt = Number.isFinite(json.expires_at)
    ? json.expires_at
    : Math.floor(Date.now() / 1000) + (Number(json.expires_in) || 0);
  return {
    access_token: json.access_token,
    refresh_token: json.refresh_token,
    expires_at: expiresAt,
    user: { id: json.user.id, email: json.user.email ?? '' },
  };
}

// 서버가 이 기기를 승인했다고 확인한 뒤에만 /vault.html 이 불러오는 자료실 화면이다.
// 브라우저는 서버 함수(/api/...)만 부른다. DB 주소나 키는 이 화면 코드에 없고, 로그인 토큰은 이 파일의 메모리에만 둔다
// (localStorage·sessionStorage·IndexedDB·쿠키에 저장하지 않으므로 새로고침하면 다시 로그인한다).
// 승인이 취소되거나 오프라인이 되면 stop() 이 화면·메모·로그인 정보를 모두 비운다.
const TEMPLATE = `
  <div id="login-section">
    <div class="notice">자료는 로그인한 본인만 볼 수 있습니다. 로그인하지 않으면 메모가 보이지 않고, 다른 사용자의 메모에는 접근할 수 없습니다.</div>
    <div class="login-box">
      <h2>로그인</h2>
      <div class="field">
        <label for="email">이메일</label>
        <input type="email" id="email" autocomplete="email" placeholder="이메일 주소">
      </div>
      <div class="field">
        <label for="password">비밀번호</label>
        <input type="password" id="password" autocomplete="current-password">
      </div>
      <button class="btn-login" id="login-btn">로그인</button>
      <div class="error-msg hidden" id="error-msg" role="alert"></div>
    </div>
  </div>

  <div id="authed-section" class="hidden">
    <div class="auth-bar">
      <span class="user-email" id="user-email"></span>
      <button class="btn-logout" id="logout-btn">로그아웃</button>
    </div>

    <fieldset class="panel" id="note-panel">
      <form class="note-form" id="note-form">
        <h2>메모 추가</h2>
        <div class="field">
          <label for="note-title">제목</label>
          <input type="text" id="note-title" maxlength="200" required autocomplete="off">
        </div>
        <div class="field">
          <label for="note-body">내용</label>
          <textarea id="note-body" rows="3" maxlength="5000"></textarea>
        </div>
        <button class="btn-login" type="submit">추가</button>
      </form>
      <div class="error-msg hidden" id="note-error" role="alert"></div>
      <ul id="notes" aria-live="polite"></ul>
    </fieldset>
  </div>
`;

class StaleSession extends Error {}

const ERROR_TEXT = {
  INVALID_NOTE: '제목은 1~200자, 내용은 5000자 이하로 입력해 주세요.',
  NOT_FOUND: '메모를 찾을 수 없습니다. 이미 지워졌을 수 있습니다.',
  FORBIDDEN: '이 메모에 접근할 수 없습니다.',
  LOGIN_REQUIRED: '서버가 로그인 정보를 확인하지 못했습니다. 로그아웃한 뒤 다시 로그인해 주세요.',
  device_verification_unavailable: '서버가 이 기기의 승인을 확인할 수 없어 자료를 열지 않았습니다.',
  device_not_approved: '서버가 이 기기를 승인하지 않아 자료를 열지 않았습니다.',
};

export function start(root, { isApproved }) {
  root.innerHTML = TEMPLATE;
  const $ = (id) => root.querySelector(`#${id}`);
  const loginSection  = $('login-section');
  const authedSection = $('authed-section');
  const userEmailEl   = $('user-email');
  const emailInput    = $('email');
  const passwordInput = $('password');
  const loginBtn      = $('login-btn');
  const logoutBtn     = $('logout-btn');
  const errorMsg      = $('error-msg');
  const notePanel     = $('note-panel');
  const noteForm      = $('note-form');
  const noteTitle     = $('note-title');
  const noteBody      = $('note-body');
  const noteError     = $('note-error');
  const notesList     = $('notes');

  let session = null;
  let stopped = false;
  let currentUserId = null;
  let notes = [];
  let editingId = null;
  let refreshing = null;

  async function postJson(path, body, token) {
    const response = await fetch(path, {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body ?? {}),
    });
    return { ok: response.ok, status: response.status, data: await response.json().catch(() => null) };
  }

  // 갱신 토큰은 한 번만 쓸 수 있어서 갱신 요청은 한 번에 하나만 보낸다.
  function refreshSession() {
    refreshing ??= (async () => {
      try {
        const { ok, status, data } = await postJson('/api/auth/refresh', { refresh_token: session?.refresh_token });
        if (ok) session = data;
        else if (status === 400 || status === 401) session = null;
      } catch { /* 네트워크 오류면 지금 세션을 그대로 둔다 */ }
      finally { refreshing = null; }
    })();
    return refreshing;
  }

  async function accessToken() {
    if (session && session.expires_at - Date.now() / 1000 < 60) await refreshSession();
    return session?.access_token ?? null;
  }

  function expire() {
    session = null;
    showUI(null);
    errorMsg.textContent = '로그인이 만료되었습니다. 다시 로그인해 주세요.';
    errorMsg.classList.remove('hidden');
    throw new StaleSession();
  }

  // 요청마다 서버의 기기 승인 상태를 먼저 새로 확인하고, 로그인 토큰만 실어 보낸다. 사용자 ID·역할은 보내지 않는다.
  async function api(method, path, body) {
    const userId = currentUserId;
    if (stopped || !(await isApproved()) || stopped) throw new StaleSession();
    const send = (token) => fetch(path, {
      method,
      cache: 'no-store',
      headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    let token = await accessToken();
    if (!token) expire();
    let response = await send(token);
    if (response.status === 401) {
      await refreshSession();
      token = session?.access_token;
      if (!token) expire();
      response = await send(token);
    }
    const data = await response.json().catch(() => null);
    if (stopped || userId !== currentUserId) throw new StaleSession();
    if (response.status === 401) expire();
    if (!response.ok) {
      throw new Error(ERROR_TEXT[data?.error] ?? `요청을 처리하지 못했습니다. (오류 ${response.status})`);
    }
    return data;
  }

  async function run(task) {
    notePanel.disabled = true;
    noteError.classList.add('hidden');
    try {
      await task();
      return true;
    } catch (error) {
      if (!(error instanceof StaleSession) && !stopped) {
        noteError.textContent = error.message;
        noteError.classList.remove('hidden');
      }
      return false;
    } finally {
      if (!stopped) notePanel.disabled = false;
    }
  }

  function plainItem(text) {
    const item = document.createElement('li');
    item.textContent = text;
    return item;
  }

  function button(label, className, onClick) {
    const el = document.createElement('button');
    el.type = 'button';
    el.className = className;
    el.textContent = label;
    el.addEventListener('click', onClick);
    return el;
  }

  function field(labelText, control, id) {
    const wrap = document.createElement('div');
    const label = document.createElement('label');
    wrap.className = 'field';
    control.id = id;
    label.htmlFor = id;
    label.textContent = labelText;
    wrap.append(label, control);
    return wrap;
  }

  function viewItem(note) {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    const text = document.createElement('span');
    const actions = document.createElement('div');
    title.textContent = note.title;
    text.className = 'note-body';
    text.textContent = note.body;
    actions.className = 'note-actions';
    actions.append(
      button('수정', 'btn', () => {
        editingId = note.id;
        renderNotes();
        notesList.querySelector('input')?.focus();
      }),
      button('삭제', 'btn btn-danger', () => removeNote(note)),
    );
    item.append(title, text, actions);
    return item;
  }

  function editItem(note) {
    const item = document.createElement('li');
    const titleInput = document.createElement('input');
    const bodyInput = document.createElement('textarea');
    const actions = document.createElement('div');
    titleInput.type = 'text';
    titleInput.maxLength = 200;
    titleInput.value = note.title;
    bodyInput.rows = 3;
    bodyInput.maxLength = 5000;
    bodyInput.value = note.body;
    actions.className = 'note-actions';
    const save = () => saveNote(note, titleInput.value, bodyInput.value);
    const cancel = () => { editingId = null; renderNotes(); };
    titleInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') { event.preventDefault(); save(); }
      if (event.key === 'Escape') cancel();
    });
    actions.append(button('저장', 'btn btn-accent', save), button('취소', 'btn', cancel));
    item.append(
      field('제목', titleInput, `edit-title-${note.id}`),
      field('내용', bodyInput, `edit-body-${note.id}`),
      actions,
    );
    return item;
  }

  function renderNotes() {
    if (stopped) return;
    if (!notes.length) {
      notesList.replaceChildren(plainItem('아직 메모가 없습니다. 위에서 첫 메모를 추가해 보세요.'));
      return;
    }
    notesList.replaceChildren(...notes.map((note) => (note.id === editingId ? editItem(note) : viewItem(note))));
  }

  async function loadNotes() {
    notesList.replaceChildren(plainItem('메모를 불러오는 중입니다.'));
    const ok = await run(async () => {
      notes = await api('GET', '/api/notes');
      renderNotes();
    });
    if (!ok && !stopped && !notes.length && currentUserId) notesList.replaceChildren(plainItem('메모를 불러오지 못했습니다.'));
  }

  function saveNote(note, title, body) {
    return run(async () => {
      const updated = await api('PUT', `/api/notes/${note.id}`, { title, body });
      notes = notes.map((n) => (n.id === note.id ? updated : n));
      editingId = null;
      renderNotes();
    });
  }

  function removeNote(note) {
    if (!window.confirm(`이 메모를 삭제할까요?\n\n${note.title}`)) return;
    return run(async () => {
      await api('DELETE', `/api/notes/${note.id}`);
      notes = notes.filter((n) => n.id !== note.id);
      if (editingId === note.id) editingId = null;
      renderNotes();
    });
  }

  noteForm.addEventListener('submit', (event) => {
    event.preventDefault();
    run(async () => {
      const title = noteTitle.value;
      const body = noteBody.value;
      const { id } = await api('POST', '/api/notes', { title, body });
      notes = [...notes, { id, title, body }];
      noteForm.reset();
      renderNotes();
    }).then((ok) => { if (ok) noteTitle.focus(); });
  });

  // 같은 사용자의 토큰 갱신에는 화면을 다시 그리지 않는다. 수정 중인 입력이 사라지기 때문이다.
  function showUI(user) {
    if (stopped) return;
    const userId = user?.id ?? null;
    if (userId === currentUserId) return;
    currentUserId = userId;
    notes = [];
    editingId = null;
    noteForm.reset();
    noteError.classList.add('hidden');
    if (!user) {
      notesList.replaceChildren();
      authedSection.classList.add('hidden');
      loginSection.classList.remove('hidden');
      return;
    }
    userEmailEl.textContent = user.email ?? '';
    loginSection.classList.add('hidden');
    authedSection.classList.remove('hidden');
    loadNotes();
  }

  loginBtn.addEventListener('click', async () => {
    const email    = emailInput.value.trim();
    const password = passwordInput.value;
    errorMsg.classList.add('hidden');
    errorMsg.textContent = '';
    if (!email || !password) {
      errorMsg.textContent = '이메일과 비밀번호를 모두 입력해 주세요.';
      errorMsg.classList.remove('hidden');
      return;
    }
    if (!(await isApproved()) || stopped) return;
    loginBtn.disabled    = true;
    loginBtn.textContent = '로그인 중…';
    let result;
    try {
      result = await postJson('/api/auth/login', { email, password });
    } catch {
      result = { ok: false, status: 0, data: { message: '서버에 연결하지 못했습니다. 인터넷 연결을 확인해 주세요.' } };
    }
    if (stopped) return;
    loginBtn.disabled    = false;
    loginBtn.textContent = '로그인';
    if (!result.ok) {
      errorMsg.textContent = result.data?.message ?? `로그인하지 못했습니다. (오류 ${result.status})`;
      errorMsg.classList.remove('hidden');
      return;
    }
    passwordInput.value = '';
    session = result.data;
    showUI(session.user);
  });

  logoutBtn.addEventListener('click', () => {
    const token = session?.access_token;
    session = null;
    showUI(null);
    // 서버에서도 이 기기의 로그인을 끊는다. 실패해도 화면은 이미 로그아웃 상태다.
    if (token) postJson('/api/auth/logout', {}, token).catch(() => {});
  });

  [emailInput, passwordInput].forEach((el) =>
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter') loginBtn.click(); })
  );

  showUI(null);

  return {
    stop() {
      stopped = true;
      session = null;
      notes = [];
      editingId = null;
      currentUserId = null;
      root.replaceChildren();
    },
  };
}

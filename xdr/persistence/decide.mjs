// patterns.json 의 패턴을 그대로 옮긴 상수. 이 파일은 아무것도 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산한다.
const MIN_REPEATS = 3;
const PATTERNS = Object.freeze({
  unsigned_new_service: { technique: 'T1543', match: /서명\s*없는[^.]*서비스|서비스[^.]*서명이\s*없|미서명[^.]*서비스|서비스[^.]*미서명|unsigned[^.]*service/iu },
  unknown_scheduled_task: { technique: 'T1053', match: /(처음\s*보는|낯선)\s*예약\s*작업|예약\s*작업\s*이름이\s*임의\s*문자열/iu },
  startup_folder_added: { technique: 'T1547.001', match: /시작\s*폴더에[^.]*추가/iu, path: /\\start menu\\programs\\startup\\/iu },
  not_in_baseline_item: { technique: 'T1543', match: /(평소|기준)\s*목록에\s*없는/iu },
  combined_mechanisms: { technique: 'T1543', match: /시작\s*프로그램과\s*예약\s*작업/iu },
  remain_after_reboot: { technique: 'T1543', match: /다시\s*켜도\s*(살아|남)/iu },
  temp_folder_payload: { technique: 'T1543', path: /\\temp\\|\\tmp\\/iu },
  random_task_name: { technique: 'T1053', match: /이름이\s*임의\s*문자열/iu, path: /\\[a-f0-9]{6,}\.(exe|cmd|bat|ps1)$/iu },
  repeat_registration: { technique: 'T1543' },
  unsigned_unverified: { technique: 'T1543', match: /서명(은|이)?\s*(아직\s*)?(확인되지\s*않|모릅니다|모름)/iu },
  tagged_without_signal: { technique: 'T1053' },
});
// 지속 장치가 실제로 등록되지 않았다는 말이 있으면 막을 근거로 세지 않는다.
const NOT_REGISTERED = /서비스\s*등록은\s*없|실행된\s*기록은\s*없/iu;

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const TECHNIQUES = ['T1543', 'T1053'];

const text = (value) => (typeof value === 'string' ? value : '');
const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');
const round = (value) => Math.min(0.99, Math.round(value * 100) / 100);

export function decide(alert) {
  const description = text(alert?.rule?.description);
  const path = text(alert?.data?.path);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const tagged = TECHNIQUES.some((id) => mitre.includes(id));
  const count = Number.parseInt(alert?.data?.count ?? '0', 10);
  const repeats = Number.isFinite(count) && count > 0 ? count : 0;
  const hit = (p) => (p.match?.test(description) ?? false) || (p.path?.test(path) ?? false);

  // 지속 장치가 실제로 등록된 근거(서비스·예약 작업·시작 폴더·기준 목록에 없는 새 항목)
  const mechanisms = [];
  if (hit(PATTERNS.unsigned_new_service)) mechanisms.push('unsigned_new_service');
  if (hit(PATTERNS.unknown_scheduled_task)) mechanisms.push('unknown_scheduled_task');
  if (hit(PATTERNS.startup_folder_added) && (PATTERNS.startup_folder_added.match.test(description) || /추가|생성|등록/u.test(description))) mechanisms.push('startup_folder_added');
  if (hit(PATTERNS.not_in_baseline_item)) mechanisms.push('not_in_baseline_item');
  if (TECHNIQUES.every((id) => mitre.includes(id)) || hit(PATTERNS.combined_mechanisms)) mechanisms.push('combined_mechanisms');
  if (hit(PATTERNS.remain_after_reboot)) mechanisms.push('remain_after_reboot');

  const temp = hit(PATTERNS.temp_folder_payload);
  const random = hit(PATTERNS.random_task_name);
  const repeated = repeats >= MIN_REPEATS && mechanisms.includes('unsigned_new_service');
  const unverified = hit(PATTERNS.unsigned_unverified);
  const notRegistered = NOT_REGISTERED.test(description);

  let confidence;
  let reason;
  if (mechanisms.length && (level >= 10 || mechanisms.length >= 2) && !(notRegistered && level < 10)) {
    // 지속 장치가 실제로 등록됐고 수준이 높거나 신호가 겹친다: 명확한 공격.
    const names = [...mechanisms];
    if (temp) names.push('temp_folder_payload');
    if (random) names.push('random_task_name');
    if (repeated) names.push('repeat_registration');
    confidence = 0.88 + Math.min(0.06, 0.02 * (mechanisms.length - 1)) + (temp ? 0.03 : 0) + (random || repeated ? 0.02 : 0) + (level >= 12 ? 0.02 : 0);
    confidence = round(confidence);
    reason = `${names.join('+')} · T1543/T1053 (수준 ${level})`;
  } else if (mechanisms.length) {
    // 등록 근거는 있지만 수준이 낮고 신호가 하나뿐이다: 애매한 시도. 알리기만 한다.
    confidence = 0.7;
    reason = `${mechanisms.join('+')} · 수준 ${level}, 신호 하나뿐`;
  } else if (temp || unverified) {
    // 임시 폴더에 파일만 있거나 서명을 모를 뿐 등록 근거가 없다: 애매한 시도.
    confidence = level >= 8 ? 0.65 : 0.6;
    reason = `${temp ? 'temp_folder_payload' : 'unsigned_unverified'} · 지속 장치 등록 근거 없음 (수준 ${level})`;
  } else if (tagged && level <= 4) {
    // 기법 표지는 있지만 수준이 낮은 평소 동작(서명된 기존 서비스·평소 시각 예약 등).
    confidence = 0.1;
    reason = `tagged_without_signal · 낮은 수준(${level})의 평소 동작`;
  } else if (tagged) {
    confidence = 0.55;
    reason = `tagged_without_signal · T1543/T1053 경보지만 등록 근거 없음 (수준 ${level})`;
  } else {
    confidence = 0.05;
    reason = '해당 패턴 없음';
  }
  return { action: actionFor(confidence), confidence, reason };
}

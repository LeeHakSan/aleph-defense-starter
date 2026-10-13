// patterns.json 의 패턴을 그대로 옮긴 상수. 이 파일은 아무것도 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산한다.
const MIN_REPEATS = 3;
const PATTERNS = Object.freeze({
  admin_group_added: { technique: 'T1078', match: /관리자\s*그룹(에|으로|에서)?[^.]*(추가|들어)/iu, not: /관리자\s*그룹(은|이)\s*아(닙|니)/iu },
  admin_command_after_promotion: { technique: 'T1068', match: /방금\s*관리자가\s*된|관리자가\s*된\s*직후|곧바로[^.]*(권한|관리자)\s*명령/iu },
  admin_command_unusual_context: { technique: 'T1068', context: /처음\s*(보는|봅니다)|낯선\s*주소|(수업|업무)\s*시간\s*밖|업무처럼\s*보이지\s*않/iu },
  session_elevated_unusual_source: { technique: 'T1068', match: /세션이\s*관리자\s*권한으로\s*바뀌/iu, source: /처음\s*(보는|봅니다)|낯선\s*주소/iu },
  borrowed_account_privilege: { technique: 'T1078', match: /다른\s*계정의\s*권한/iu },
  admin_group_flap: { technique: 'T1078', match: /관리자\s*그룹에서\s*빠진[^.]*다시\s*관리자/iu },
  multi_account_admin_add: { technique: 'T1078' },
  off_hours_privilege_use: { technique: 'T1078', match: /(수업|업무)\s*시간\s*밖|업무처럼\s*보이지\s*않/iu },
  admin_command_usual_context: { technique: 'T1068' },
  elevation_without_followup: { technique: 'T1068', match: /권한\s*상승[^.]*(취소|명령은\s*없|변경은\s*없)/iu },
  failed_admin_command: { technique: 'T1068', match: /명령이\s*실패/iu },
  non_admin_group_change: { technique: 'T1078', match: /(새\s*로컬\s*그룹|그룹[^.]*(추가|설명|만들어|바뀌))/iu },
  tagged_without_signal: { technique: 'T1068' },
});
// 관리자 명령을 실행했다는 말
const ADMIN_COMMAND = /관리자\s*명령|권한\s*명령|명령\s*실행/iu;

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const TECHNIQUES = ['T1068', 'T1078'];

const text = (value) => (typeof value === 'string' ? value : '');
const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');
const round = (value) => Math.min(0.99, Math.round(value * 100) / 100);

export function decide(alert) {
  const description = text(alert?.rule?.description);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const tagged = TECHNIQUES.some((id) => mitre.includes(id));
  const count = Number.parseInt(alert?.data?.count ?? '0', 10);
  const repeats = Number.isFinite(count) && count > 0 ? count : 0;

  const groupAdded = PATTERNS.admin_group_added.match.test(description) && !PATTERNS.admin_group_added.not.test(description);
  const command = ADMIN_COMMAND.test(description);
  const unusual = PATTERNS.admin_command_unusual_context.context.test(description);

  // 권한 상승이 실제로 일어났다는 근거
  const signals = [];
  if (groupAdded) signals.push('admin_group_added');
  if (command && PATTERNS.admin_command_after_promotion.match.test(description)) signals.push('admin_command_after_promotion');
  if (command && unusual) signals.push('admin_command_unusual_context');
  if (PATTERNS.session_elevated_unusual_source.match.test(description) && PATTERNS.session_elevated_unusual_source.source.test(description)) signals.push('session_elevated_unusual_source');
  if (command && PATTERNS.borrowed_account_privilege.match.test(description)) signals.push('borrowed_account_privilege');
  if (PATTERNS.admin_group_flap.match.test(description)) signals.push('admin_group_flap');
  if (groupAdded && repeats >= MIN_REPEATS) signals.push('multi_account_admin_add');
  const offHours = PATTERNS.off_hours_privilege_use.match.test(description) && signals.length > 0;

  let confidence;
  let reason;
  if (signals.length && (level >= 10 || signals.length >= 2)) {
    // 관리자 권한 상승·사용 근거가 있고 수준이 높거나 신호가 겹친다: 명확한 공격.
    const names = [...signals];
    if (offHours) names.push('off_hours_privilege_use');
    confidence = 0.88 + Math.min(0.06, 0.02 * (signals.length - 1)) + (offHours ? 0.02 : 0) + (level >= 12 ? 0.02 : 0);
    confidence = round(confidence);
    reason = `${names.join('+')} · T1068/T1078 (수준 ${level})`;
  } else if (signals.length) {
    confidence = 0.7;
    reason = `${signals.join('+')} · 수준 ${level}, 신호 하나뿐`;
  } else if (command || PATTERNS.elevation_without_followup.match.test(description)) {
    // 관리자 명령이 평소 모양으로 한 번 있었거나 상승이 취소·실패했다: 애매한 시도. 알리기만 한다.
    const name = PATTERNS.failed_admin_command.match.test(description) ? 'failed_admin_command'
      : command ? 'admin_command_usual_context' : 'elevation_without_followup';
    confidence = level >= 8 ? 0.65 : 0.6;
    reason = `${name} · 권한 상승 근거 없음 (수준 ${level})`;
  } else if (PATTERNS.non_admin_group_change.match.test(description) && tagged) {
    confidence = 0.55;
    reason = `non_admin_group_change · 관리자 그룹이 아닌 변경 (수준 ${level})`;
  } else if (tagged) {
    confidence = 0.55;
    reason = `tagged_without_signal · T1068/T1078 경보지만 권한 상승 근거 없음 (수준 ${level})`;
  } else {
    confidence = 0.05;
    reason = '해당 패턴 없음';
  }
  return { action: actionFor(confidence), confidence, reason };
}

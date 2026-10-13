// patterns.json 의 패턴을 그대로 옮긴 상수. 이 파일은 아무것도 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산한다.
const LARGE_BYTES = 50000000;
const BULK_FILES = 50;
const MODERATE_BYTES = 5000000;
const MODERATE_FILES = 10;
const MIN_REPEATS = 3;
const PATTERNS = Object.freeze({
  large_transfer: { technique: 'T1048' },
  new_destination: { technique: 'T1048', match: /처음\s*(보는|봅니다)|평소와\s*다른\s*(주소|목적지)/iu },
  unusual_port: { technique: 'T1048', match: /평소에\s*쓰지\s*않던\s*포트/iu },
  off_hours_transfer: { technique: 'T1048', match: /(수업|업무)\s*시간\s*밖/iu },
  compressed_archive_out: { technique: 'T1048', match: /압축\s*파일/iu, not: /외부\s*전송은\s*아직\s*없|만들었습니다|연\s*뒤/iu },
  repeat_transfer: { technique: 'T1041', match: /반복|연속/iu },
  multi_destination: { technique: 'T1048', match: /목적지\s*(두|2|세|3)\s*곳/iu },
  external_bulk_copy: { technique: 'T1041', match: /자료실\s*전체[^.]*(외부|바깥)[^.]*복사/iu },
  command_channel: { technique: 'T1041', match: /명령\s*통로/iu },
  moderate_volume: { technique: 'T1048' },
  tagged_without_signal: { technique: 'T1048' },
});
// 전송이 아직 없었거나 실패했다는 말이 있으면 큰 전송으로 세지 않는다.
const NOT_SENT = /외부\s*전송은\s*아직\s*없|전송이\s*실패|파일\s*전송은\s*없/iu;

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const TECHNIQUES = ['T1041', 'T1048'];

const text = (value) => (typeof value === 'string' ? value : '');
const numberOf = (value) => {
  const n = Number.parseInt(value ?? '0', 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
};
const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');
const round = (value) => Math.min(0.99, Math.round(value * 100) / 100);

export function decide(alert) {
  const description = text(alert?.rule?.description);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const tagged = TECHNIQUES.some((id) => mitre.includes(id));
  const bytes = numberOf(alert?.data?.bytes);
  const files = numberOf(alert?.data?.files);
  const count = numberOf(alert?.data?.count);
  const hit = (name) => PATTERNS[name].match.test(description);

  const large = bytes >= LARGE_BYTES || files >= BULK_FILES;
  const notSent = NOT_SENT.test(description);

  // 이상 징후: 처음 보는 목적지, 평소에 쓰지 않던 포트, 업무 시간 밖, 반복, 여러 목적지, 자료실 전체 복사
  const anomalies = [];
  if (hit('new_destination')) anomalies.push('new_destination');
  if (hit('unusual_port')) anomalies.push('unusual_port');
  if (hit('off_hours_transfer')) anomalies.push('off_hours_transfer');
  if (count >= MIN_REPEATS || hit('repeat_transfer')) anomalies.push('repeat_transfer');
  if (hit('multi_destination')) anomalies.push('multi_destination');
  if (hit('external_bulk_copy')) anomalies.push('external_bulk_copy');
  const supports = [];
  if (PATTERNS.compressed_archive_out.match.test(description) && !PATTERNS.compressed_archive_out.not.test(description)) supports.push('compressed_archive_out');
  if (hit('command_channel')) supports.push('command_channel');

  let confidence;
  let reason;
  if (large && !notSent && anomalies.length && (level >= 10 || anomalies.length >= 2)) {
    // 큰 전송이 이상 징후와 함께 있다: 명확한 공격.
    const names = ['large_transfer', ...anomalies, ...supports];
    confidence = 0.88 + Math.min(0.06, 0.02 * (anomalies.length - 1)) + (supports.length ? 0.01 : 0) + (bytes >= 200000000 || files >= 200 ? 0.02 : 0) + (level >= 12 ? 0.02 : 0);
    confidence = round(confidence);
    reason = `${names.join('+')} · T1041/T1048 (${Math.round(bytes / 1000000)}MB, 파일 ${files}건, 수준 ${level})`;
  } else if (large && !notSent) {
    // 큰 전송이지만 이상 징후가 없다(평소 목적지·평소 시각일 수 있다): 애매한 시도. 알리기만 한다.
    confidence = 0.7;
    reason = `large_transfer · 이상 징후 없음 (${Math.round(bytes / 1000000)}MB, 수준 ${level})`;
  } else if (anomalies.length || supports.length || bytes >= MODERATE_BYTES || files >= MODERATE_FILES) {
    // 큰 전송은 아니다: 낯선 목적지·반복·압축·조금 큰 전송 정도의 애매한 시도. 알리기만 한다.
    const names = anomalies.length || supports.length ? [...anomalies, ...supports] : ['moderate_volume'];
    confidence = level >= 8 ? 0.65 : 0.6;
    reason = `${names.join('+')} · 큰 전송 아님 (${bytes}바이트, 파일 ${files}건, 수준 ${level})`;
  } else if (tagged && level <= 4) {
    confidence = 0.1;
    reason = `tagged_without_signal · 작은 평소 전송 (수준 ${level})`;
  } else if (tagged) {
    confidence = 0.55;
    reason = `tagged_without_signal · T1041/T1048 경보지만 유출 근거 없음 (수준 ${level})`;
  } else {
    confidence = 0.05;
    reason = '해당 패턴 없음';
  }
  return { action: actionFor(confidence), confidence, reason };
}

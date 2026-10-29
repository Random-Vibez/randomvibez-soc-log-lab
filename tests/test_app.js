'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
const api = require('../app.js');

const base = { family: 'linux-messages', totalRows: 80, basePositives: 3, difficulty: 1, seed: 'TEST-PRIVATE-SEED-XYZ' };
function contentProjection(dataset) {
  const removeVolatileFields = (row) => {
    const copy = { ...row };
    delete copy.record_id;
    delete copy['event.id'];
    delete copy.TrainingRecordId;
    delete copy.process_id;
    delete copy.ProcessID;
    for (const field of ['message', 'SyslogMessage', 'event.original', 'analystNote']) {
      if (typeof copy[field] === 'string') copy[field] = copy[field].replace(/\[\d+\]/g, '[]');
    }
    return copy;
  };
  return {
    config: { ...dataset.config, seed: '<private>' },
    logs: dataset.logs.map(removeVolatileFields),
    rawSyslog: dataset.rawSyslog && dataset.rawSyslog
      .replace(/\s\d+ SYNTH - /g, ' <fresh-pid> SYNTH - ')
      .replace(/\[\d+\]/g, '[]')
      .replace(/\[training_record_id=[^\]]+\]/g, '[training_record_id=<fresh-id>]'),
    findings: dataset.findings.map(({ rowIds, evidence, ...finding }) => ({ ...finding, analystNote: finding.analystNote.replace(/\[\d+\]/g, '[]'), evidence: evidence.map(({ recordId, message, ...item }) => ({ ...item, message: String(message).replace(/\[\d+\]/g, '[]') })) }))
  };
}
function logMessage(row) { return String(row.message || row.SyslogMessage || row['event.original'] || ''); }
function logRecordId(row) { return row.record_id || row['event.id'] || row.TrainingRecordId; }
function logPid(row) { return row.process_id || row.ProcessID || null; }
function expectedSourceIp(message) {
  const ip = '((?:[0-9]{1,3}\\.){3}[0-9]{1,3})';
  const direct = new RegExp(`\\bfrom\\s+${ip}\\b`, 'i').exec(message);
  if (direct) return direct[1];
  const relay = new RegExp(`\\b(?:connect|connection)\\s+from\\s+[^[]+\\[${ip}\\]`, 'i').exec(message);
  return relay ? relay[1] : null;
}
function structuredSourceIp(row) {
  if (Object.prototype.hasOwnProperty.call(row, 'source_ip')) return row.source_ip;
  if (Object.prototype.hasOwnProperty.call(row, 'source.ip')) return row['source.ip'];
  return undefined;
}
function logTimestamp(row) { return row.timestamp || row.TimeGenerated || row['@timestamp'] || row.time; }
const printCss = fs.readFileSync(require.resolve('../styles.css'), 'utf8');
const printBlock = /@media\s+print\s*\{([\s\S]*)\}\s*$/.exec(printCss)?.[1];
assert(printBlock, 'a dedicated print media rule is present');
assert.match(printBlock, /body\s*\{[^}]*background:\s*#fff[^}]*color:\s*#111/i, 'printed page uses a light background and dark text');
assert.match(printBlock, /\.eyebrow\s*\{[^}]*color:\s*#111/i, 'accent text remains high-contrast in print');
assert.match(printBlock, /\.controls[^}]*display:\s*none/i, 'interactive generator controls are excluded from print');
assert.match(printBlock, /\.log-preview\s*\{[^}]*max-height:\s*none[^}]*overflow:\s*visible[^}]*background:\s*#fff[^}]*color:\s*#111/i, 'synthetic log output prints without clipping on a readable light surface');
assert.match(printBlock, /\.privacy-note[^}]*background:\s*#fff/i, 'privacy boundary remains readable in print');
assert.match(printBlock, /\.notes\s*\{[^}]*background:\s*#fff/i, 'safety notes remain readable in print');
const cookieBannerRule = /\.cookie-banner\s*\{([^}]*)\}/.exec(printCss)?.[1];
assert(cookieBannerRule, 'app-local cookie banner rule is present without the shared site stylesheet');
assert.match(cookieBannerRule, /position:\s*static/i, 'cookie notice remains in normal document flow');
assert.doesNotMatch(cookieBannerRule, /(?:^|;)\s*(?:right|bottom|z-index):/i, 'cookie notice has no viewport anchoring or overlay stacking');
assert.match(cookieBannerRule, /width:\s*min\(780px,\s*calc\(100%\s*-\s*2rem\)\)/i, 'desktop notice matches the shared responsive panel width');
assert.match(cookieBannerRule, /padding:\s*\.85rem\s+1rem\s+\.85rem\s+1\.1rem/i, 'notice panel uses the shared compact padding');
assert.match(cookieBannerRule, /color:\s*#15213f[^}]*background:\s*#fff/i, 'notice uses the shared white card and dark text');
assert.match(cookieBannerRule, /border-radius:\s*16px[^}]*box-shadow:\s*0\s+18px\s+55px\s+rgba\(2,8,30,\.34\)/i, 'notice panel retains shared rounding and elevation');
assert.match(printCss, /\.cookie-banner-eyebrow\s*\{[^}]*color:\s*#5140a3[^}]*text-transform:\s*uppercase/i, 'notice eyebrow retains its shared treatment');
assert.match(printCss, /\.cookie-banner-text\s*\{[^}]*color:\s*#3f4b68[^}]*font-size:\s*\.8rem/i, 'notice copy retains its readable compact styling');
assert.match(printCss, /\.cookie-banner-accept\s*\{[^}]*background:\s*linear-gradient\(120deg,#202b63,#633aa1\)/i, 'accept button uses the shared purple gradient');
assert.match(printCss, /\.cookie-banner-accept:focus-visible\s*\{[^}]*outline:\s*3px\s+solid\s+#5a4bff[^}]*outline-offset:\s*3px/i, 'keyboard focus remains visibly outlined');
assert.match(printCss, /@media\s*\(max-width:\s*560px\)\s*\{\.cookie-banner\s*\{[^}]*flex-direction:\s*column[^}]*width:\s*calc\(100%\s*-\s*1\.5rem\)[^}]*\}\.cookie-banner-accept\s*\{[^}]*width:\s*100%/i, 'narrow mobile notice stacks its copy and full-width accept button');
assert.doesNotMatch(printCss, /@media\s*\(max-width:\s*480px\)\s*\{\.shell\s*\{\s*padding-bottom:\s*calc\(3rem\s*\+\s*13rem\)/i, 'mobile shell has no extra fixed-banner clearance');
const appHtml = fs.readFileSync(require.resolve('../index.html'), 'utf8');
const cookieScript = fs.readFileSync(require.resolve('../../../cookie-banner.js'), 'utf8');
assert.match(appHtml, /<link\s+rel="stylesheet"\s+href="styles\.css"\s*>/i, 'app keeps loading its local stylesheet');
assert.doesNotMatch(appHtml, /(?:\.\.\/|\/)styles\.css/i, 'app does not load the root site stylesheet');
assert.match(appHtml, /<footer>[\s\S]*?<\/footer>\s*<script src="app\.js" defer><\/script>\s*<script src="\.\.\/cookie-banner\.js" defer><\/script>\s*<\/body>/i, 'shared notice script runs after app content at the bottom of the document');
assert.match(cookieScript, /document\.body\.appendChild\(banner\)/, 'shared notice is appended as the final in-flow body child');
assert.match(cookieScript, /A small site note[\s\S]*?If you accept, RandomVibez stores one essential first-party cookie[\s\S]*?It does not track activity, measure visits, or collect personal information\.[\s\S]*?You can browse normally; accepting simply hides this notice for up to one year\.[\s\S]*?Privacy details/i, 'shared notice copy remains unchanged');
assert.match(cookieScript, /const COOKIE_NAME = 'randomvibez_cookie_notice';[\s\S]*?const COOKIE_VALUE = 'accepted';[\s\S]*?if \(hasAccepted\) return;/, 'shared acceptance cookie and existing dismissal boundary remain intact');
assert.match(cookieScript, /Max-Age=31536000; Path=\/; SameSite=Lax[\s\S]*?banner\.remove\(\)/, 'acceptance still stores the one-year first-party preference and hides the notice');
assert.match(cookieScript, /<button class="cookie-banner-accept" type="button">Accept<\/button>/, 'shared notice retains its accept button copy');
const first = api.makeDataset(base);
const again = api.makeDataset(base);
assert.deepEqual(contentProjection(first), contentProjection(again), 'same settings and seed reproduce scenario content and ordering despite fresh IDs/PIDs');
assert.notDeepEqual(first.logs.map((row) => row.record_id), again.logs.map((row) => row.record_id), 'fresh record IDs differ across generations with the same seed');
assert.deepEqual(first.logs.map((row) => logMessage(row).replace(/\[\d+\]/g, '[]')), again.logs.map((row) => logMessage(row).replace(/\[\d+\]/g, '[]')), 'same seed preserves event messages apart from volatile PIDs');
assert(first.logs.some((row, index) => logPid(row) !== '-' && logPid(again.logs[index]) !== '-'), 'test dataset includes generated process IDs');
assert(first.logs.every((row, index) => logPid(row) === '-' || logPid(again.logs[index]) === '-' || logPid(row) !== logPid(again.logs[index])), 'process IDs are fresh per generation and do not encode deterministic planted-block indices');
assert.notDeepEqual(contentProjection(api.makeDataset({ ...base, seed: 'another-seed' })), contentProjection(first), 'changing seed changes scenario content/order after volatile IDs are normalized');
const plantedRowIdsForPidCheck = new Set(first.answerKey.findings.flatMap((finding) => finding.rowIds));
const pidRows = first.logs.filter((row) => /^\d+$/.test(String(logPid(row))));
const plantedPids = pidRows.filter((row) => plantedRowIdsForPidCheck.has(logRecordId(row))).map((row) => Number(logPid(row)));
const benignPids = pidRows.filter((row) => !plantedRowIdsForPidCheck.has(logRecordId(row))).map((row) => Number(logPid(row)));
assert(plantedPids.some((pid) => benignPids.some((other) => pid < other)) && plantedPids.some((pid) => benignPids.some((other) => pid > other)), 'sorting process IDs interleaves planted and benign rows instead of exposing the allocation block');
assert(first.logs.every((row) => structuredSourceIp(row) === undefined || structuredSourceIp(row) === expectedSourceIp(logMessage(row))), 'structured source-IP fields match only source addresses present in the same message');
assert.notEqual(api.createSeed(), api.createSeed(), 'private default seeds are freshly generated');
assert.equal(api.normalizeConfig({ ...base, seed: '' }).seed === 'RV-SOC-01', false, 'empty seed never falls back to the public literal');
assert.notEqual(api.normalizeConfig({ ...base, seed: '' }).seed, api.normalizeConfig({ ...base, seed: '' }).seed, 'each empty seed request generates a fresh private seed');
assert.equal(fs.readFileSync(require.resolve('../index.html'), 'utf8').includes('value="RV-SOC-01"'), false, 'HTML has no known static default seed');
assert.equal(first.logs.length, 80, 'requested row count is exact');
assert.equal(first.findings.length, 3, 'difficulty one preserves baseline positive count');
assert.equal(first.rawSyslog.trim().split('\n').length, 80, 'Linux export includes one raw syslog line per row');
assert.equal(new Set(first.logs.map((row) => row.record_id)).size, 80, 'record identifiers are unique');
assert(first.logs.every((row) => row.host.endsWith('.example.test')), 'hostnames are reserved examples');
const mentionedIps = [...JSON.stringify(first).matchAll(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g)].map((match) => match[0]);
assert(mentionedIps.every((ip) => /^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)), 'all embedded IPv4 addresses are reserved documentation ranges');
assert(first.logs.every((row) => structuredSourceIp(row) === undefined || structuredSourceIp(row) === expectedSourceIp(logMessage(row))), 'structured source-IP fields match the source address actually written in each message');
assert(!JSON.stringify(first).match(/password\s*[:=]\s*[^\s,}]+/i), 'no password values are embedded');
assert.equal(api.makeDataset({ ...base, difficulty: 5 }).findings.length, 7, 'difficulty adds one planted finding per tier above one');
assert.equal(api.makeDataset({ ...base, difficulty: 5 }).logs.length, 80, 'higher difficulty retains exact total row count');
assert.equal(api.makeDataset({ ...base, basePositives: 100, difficulty: 5, totalRows: 20 }).findings.length, 20, 'positive findings are bounded by row count');
assert.equal(api.makeDataset({ ...base, basePositives: 0, difficulty: 1 }).findings.length, 0, 'zero baseline detections produces no findings');
assert.notDeepEqual(api.makeDataset({ ...base, seed: 'another-seed' }).logs, first.logs, 'changing seed changes the deterministic dataset');
assert.equal(api.makeDataset({ ...base, family: 'sentinel' }).logs[0].TrainingOnly, true, 'Sentinel-shaped output declares training-only');
assert('SyslogMessage' in api.makeDataset({ ...base, family: 'sentinel' }).logs[0], 'Sentinel profile uses documented Syslog table-style field names');
assert.equal(api.makeDataset({ ...base, family: 'crowdstrike' }).logs[0].TrainingOnly, true, 'CrowdStrike-shaped output declares training-only');
assert('Cps.version' in api.makeDataset({ ...base, family: 'crowdstrike' }).logs[0], 'CrowdStrike example is CPS/ECS-inspired, not an alert export');
assert.equal(api.makeDataset({ ...base, family: 'rapid7' }).logs[0].TrainingOnly, true, 'Rapid7 generic output declares training-only');
assert(!('event_type' in api.makeDataset({ ...base, family: 'rapid7' }).logs[0]), 'generic Rapid7-shaped output does not falsely claim UEF event schema');
assert.equal(api.makeDataset({ ...base, family: 'linux-maillog' }).rawSyslog.trim().split('\n').length, 80, 'maillog family exports raw syslog');
assert(api.makeDataset({ ...base, family: 'linux-maillog' }).logs.every((row) => /^(postfix\/|dovecot\[)/.test(row.message)), 'maillog family contains only synthetic mail events');
const families = ['linux-messages', 'linux-syslog', 'linux-maillog', 'crowdstrike', 'sentinel', 'rapid7'];
for (const family of families) {
  for (let difficulty = 1; difficulty <= 5; difficulty += 1) {
    const dataset = api.makeDataset({ ...base, family, totalRows: 20, basePositives: 2, difficulty });
    assert.equal(dataset.logs.length, 20, `${family} difficulty ${difficulty} has the exact row count`);
    for (const finding of dataset.findings) {
      const linkedIds = new Set(finding.rowIds);
      const linkedRowsByTimestamp = dataset.logs.filter((row) => linkedIds.has(logRecordId(row)))
        .sort((left, right) => Date.parse(logTimestamp(left)) - Date.parse(logTimestamp(right)));
      assert.deepEqual(linkedRowsByTimestamp.map(logRecordId), finding.rowIds, `${family} difficulty ${difficulty} linked scenario events remain chronological when emitted timestamps are sorted`);
    }
    const sourceIpMismatches = dataset.logs.filter((row) => structuredSourceIp(row) !== undefined && structuredSourceIp(row) !== expectedSourceIp(logMessage(row))).map((row) => ({ source: structuredSourceIp(row), expected: expectedSourceIp(logMessage(row)), message: logMessage(row) }));
    assert.equal(sourceIpMismatches.length, 0, `${family} difficulty ${difficulty} structured source-IP fields agree with their message: ${JSON.stringify(sourceIpMismatches)}`);
    assert(!JSON.stringify(dataset).includes('training-session-'), `${family} difficulty ${difficulty} has no literal session/group markers`);
    assert(!api.jsonLines(dataset).includes('training-session-'), `${family} difficulty ${difficulty} analyst JSONL has no session/group markers`);
    assert(!String(dataset.rawSyslog || '').includes('training-session-'), `${family} difficulty ${difficulty} raw output has no session/group markers`);
    assert(!api.jsonLines(dataset).includes(base.seed), `${family} difficulty ${difficulty} analyst export excludes the trainer seed`);
    assert(!String(dataset.rawSyslog || '').includes(base.seed), `${family} difficulty ${difficulty} raw export excludes the trainer seed`);
    assert.equal(dataset.answerKey.seed, base.seed, `${family} difficulty ${difficulty} answer key contains the trainer seed`);
    const rowIds = dataset.logs.map((row) => row.record_id || row['event.id'] || row.TrainingRecordId);
    assert.equal(new Set(rowIds).size, rowIds.length, `${family} difficulty ${difficulty} CSPRNG record IDs are unique`);
    assert.equal(dataset.findings.length, 1 + difficulty, `${family} difficulty ${difficulty} adds the expected findings`);
    assert(dataset.findings.every((finding) => finding.rowIds.every((id) => dataset.logs.some((row) => Object.values(row).includes(id)))), `${family} difficulty ${difficulty} answer-key references resolve`);
    for (const finding of dataset.findings) {
      assert.equal(finding.evidence.length, finding.rowIds.length, `${family} finding evidence/message count matches linked IDs`);
      for (const evidence of finding.evidence) {
        const row = dataset.logs.find((candidate) => Object.values(candidate).includes(evidence.recordId));
        const actualMessage = row && (row.message || row.SyslogMessage || row['event.original']);
        assert.equal(actualMessage, evidence.message, `${family} answer-key evidence exactly matches the emitted row`);
      }
      if (finding.rowIds.length === 1) assert(finding.analystNote.includes(finding.evidence[0].message), `${family} single-row note cites only its emitted message`);
      else assert(finding.analystNote.includes(`contains ${finding.rowIds.length} emitted linked rows`), `${family} multi-row note states the exact emitted count`);
      assert(finding.explanation.includes(`exactly ${finding.rowIds.length} emitted row IDs`), `${family} explanation is bounded to emitted rows`);
    }
    assert.equal(Boolean(dataset.rawSyslog), family.startsWith('linux-'), `${family} raw syslog availability matches family`);
  }
}
const shuffledFixture = api.makeDataset({ ...base, totalRows: 80, basePositives: 3, difficulty: 3 });
assert.notDeepEqual(shuffledFixture.logs.map(logRecordId), [...shuffledFixture.logs].sort((left, right) => Date.parse(logTimestamp(left)) - Date.parse(logTimestamp(right))).map(logRecordId), 'rows remain shuffled in emitted order while timestamps stay attached to records');
const timestampLeakFamilies = ['linux-messages', 'linux-syslog', 'linux-maillog', 'crowdstrike', 'sentinel', 'rapid7'];
for (const family of timestampLeakFamilies) {
  for (let difficulty = 1; difficulty <= 5; difficulty += 1) {
    const dataset = api.makeDataset({ ...base, family, totalRows: 80, basePositives: 3, difficulty, seed: `TS-LEAK-${family}-${difficulty}` });
    const plantedIds = new Set(dataset.answerKey.findings.flatMap((finding) => finding.rowIds));
    assert(plantedIds.size > 0, `${family} difficulty ${difficulty} has planted rows for the timestamp-interleave check`);
    assert(dataset.logs.some((row) => !plantedIds.has(logRecordId(row))), `${family} difficulty ${difficulty} has benign rows for the timestamp-interleave check`);
    const positivesByTime = [...dataset.logs]
      .sort((left, right) => Date.parse(logTimestamp(left)) - Date.parse(logTimestamp(right)))
      .map((row) => plantedIds.has(logRecordId(row)));
    const firstBenign = positivesByTime.indexOf(false);
    const firstPlanted = positivesByTime.indexOf(true);
    assert(firstBenign !== -1 && firstPlanted !== -1, `${family} difficulty ${difficulty} timestamp order contains both planted and benign rows`);
    assert(positivesByTime.slice(firstBenign).some(Boolean), `${family} difficulty ${difficulty} sorting by timestamp interleaves planted rows after the first benign row`);
    assert(positivesByTime.slice(firstPlanted).some((isPlanted) => !isPlanted), `${family} difficulty ${difficulty} sorting by timestamp interleaves benign rows after the first planted row`);
  }
}
assert.equal(api.makeDataset({ ...base, family: 'linux-syslog', totalRows: 20, basePositives: 0, difficulty: 1 }).findings.length, 0, 'zero positives at difficulty one stays a baseline-only set');
assert.equal(api.makeDataset({ ...base, family: 'linux-syslog', totalRows: 20, basePositives: 0, difficulty: 5 }).findings.length, 4, 'difficulty additions still apply when base positives are zero');
const bounded = api.makeDataset({ ...base, family: 'sentinel', totalRows: 20, basePositives: 100, difficulty: 5 });
assert.equal(bounded.logs.length, 20, 'boundary capacity never exceeds total rows');
assert.equal(bounded.findings.length, 20, 'planted findings are bounded by row count');
const csCheck = api.makeDataset({ ...base, family: 'crowdstrike', basePositives: 5, difficulty: 2 });
assert.deepEqual(new Set(csCheck.logs.map((row) => row['event.category'][0])), new Set(['authentication', 'iam', 'host', 'email', 'network']), 'CrowdStrike-shaped categories reflect varied source events');
assert(csCheck.logs.every((row) => row['event.outcome'] === null || ['failure', 'success'].includes(row['event.outcome'])), 'vendor outcomes remain observed success/failure or absent');
const failureLog = csCheck.logs.find((row) => String(row['event.original']).includes('Failed password'));
const successLog = csCheck.logs.find((row) => String(row['event.original']).includes('Accepted publickey'));
assert.equal(failureLog?.['event.outcome'], 'failure', 'failed authentication is marked failure');
assert.equal(successLog?.['event.outcome'], 'success', 'successful authentication remains success even when planted');
const syslogCheck = api.makeDataset({ ...base, family: 'linux-syslog', basePositives: 5, difficulty: 3 });
assert(syslogCheck.rawSyslog.includes(' kernel '), 'kernel program name is preserved in RFC 5424-shaped output');
const facilityFor = (program) => {
  const name = program.toLowerCase();
  if (name === 'kernel') return ['kern', 0];
  if (name.startsWith('postfix') || name === 'dovecot') return ['mail', 2];
  if (name === 'cron') return ['cron', 9];
  if (['sshd', 'sudo', 'audit'].includes(name)) return ['authpriv', 10];
  return ['daemon', 3];
};
for (const row of syslogCheck.logs) {
  const [facility, code] = facilityFor(row.process);
  assert.equal(row.facility, facility, `${row.process} receives the mapped Linux facility`);
  assert.equal(row.facility_code, code, `${row.process} receives the matching PRI facility code`);
  const raw = syslogCheck.rawSyslog.split(String.fromCharCode(10)).find((line) => line.includes(row.record_id));
  assert(raw.includes(` ${row.process} ${row.process_id} `), `${row.process} and PID remain aligned in the raw header`);
  let embeddedPid = '-';
  if (row.message.startsWith(`${row.process}[`)) {
    const pidEnd = row.message.indexOf(']', row.process.length + 1);
    assert(pidEnd > row.process.length + 1, `${row.process} message has a closed PID token`);
    embeddedPid = row.message.slice(row.process.length + 1, pidEnd);
  }
  assert.equal(row.process_id, embeddedPid, `${row.process} JSON/syslog process ID matches its message or is absent`);
  const pri = /^<([0-9]+)>1 /.exec(raw);
  assert(pri, 'raw syslog has an RFC 5424 PRI/version prefix');
  assert.equal(Number(pri[1]), code * 8 + (row.severity === 'Warning' ? 4 : 6), 'raw PRI combines mapped facility and severity codes');
}
assert.equal(api.makeDataset({ ...base, family: 'rapid7' }).rawSyslog, null, 'raw syslog download is limited to Linux families');
assert.equal(api.jsonLines(first).trim().split('\n').length, 80, 'analyst export is line-delimited JSON');
assert(!api.jsonLines(first).includes(base.seed), 'analyst JSONL excludes the private trainer seed');
assert(!first.rawSyslog.includes(base.seed), 'raw syslog excludes the private trainer seed');
assert.equal(first.answerKey.seed, base.seed, 'answer key alone carries the trainer seed');
assert(!api.jsonLines(first).includes('findingIndex'), 'analyst export excludes internal ground-truth labels');
assert.equal(first.answerKey.findings[0].rowIds.length, 1, 'key identifies trigger record at tier one');
assert(first.rawSyslog.includes(first.answerKey.findings[0].rowIds[0]), 'raw syslog contains the answer-key cross-reference ID');
const rawMessageIds = first.rawSyslog.trim().split(String.fromCharCode(10)).map((line) => line.split(' ')[5]);
assert.equal(new Set(rawMessageIds).size, 1, 'raw syslog uses one uniform opaque MSGID for planted and benign rows');
assert.equal(rawMessageIds[0], 'SYNTH', 'raw syslog MSGID does not encode finding groups');
assert(first.logs.every((row) => /^SYN-[0-9a-f]{32}$/.test(row.record_id)), 'record IDs are CSPRNG-shaped and carry no deterministic seed/index');
const plantedRecordIds = new Set(first.answerKey.findings.flatMap((finding) => finding.rowIds));
assert(plantedRecordIds.size > 0 && [...plantedRecordIds].every((id) => first.logs.some((row) => row.record_id === id)), 'answer-key IDs resolve exactly to analyst records');
assert(api.makeDataset({ ...base, difficulty: 5 }).answerKey.findings.every((f) => f.rowIds.length >= 2), 'higher difficulty adds correlated supporting records when room allows');
for (const [family, idField] of [['crowdstrike', 'event.id'], ['sentinel', 'TrainingRecordId'], ['rapid7', 'record_id']]) {
  const shaped = api.makeDataset({ ...base, family });
  const recordIds = shaped.logs.map((row) => row[idField]);
  assert(shaped.answerKey.findings.every((finding) => finding.rowIds.every((id) => recordIds.includes(id))), `${family} answer-key IDs cross-reference analyst rows`);
}
assert.throws(() => api.makeDataset({ ...base, totalRows: 19 }), /Total rows/);
assert.throws(() => api.makeDataset({ ...base, difficulty: 6 }), /Difficulty/);
assert.throws(() => api.makeDataset({ ...base, family: 'unknown' }), /log family/);

// Exercise browser initialization and real click-handler wiring with a minimal DOM.
class FakeElement {
  constructor(id, value = '') { this.id = id; this.value = value; this.textContent = ''; this.disabled = false; this.open = false; this.listeners = {}; this.children = []; }
  addEventListener(type, callback) { (this.listeners[type] ||= []).push(callback); }
  dispatch(type, event = {}) { for (const callback of this.listeners[type] || []) callback({ target: this, ...event }); }
  appendChild(child) { this.children.push(child); child.parentNode = this; }
  remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((child) => child !== this); }
  click() { this.clicked = true; }
}
const elementIds = ['generator','seed','preview','status','show-key','download-raw','family','total-rows','base-positives','difficulty','finding-count','extra-count','row-count','seed-label','difficulty-description','preview-note','new-seed','download-logs','download-key','answer-key'];
const elements = Object.fromEntries(elementIds.map((id) => [id, new FakeElement(id)]));
Object.assign(elements.family, { value: 'linux-messages' });
Object.assign(elements['total-rows'], { value: '20' });
Object.assign(elements['base-positives'], { value: '2' });
Object.assign(elements.difficulty, { value: '2' });
Object.assign(elements.seed, { value: '' });
const document = { readyState: 'complete', body: new FakeElement('body'), getElementById: (id) => elements[id] || null, createElement: (tag) => new FakeElement(tag) };
const blobs = [];
const runtime = { document, window: null, crypto: webcrypto, Blob: class { constructor(parts, options) { this.parts = parts; this.type = options.type; blobs.push(this); } }, URL: { createObjectURL: () => 'blob:runtime-test', revokeObjectURL: () => {} }, setTimeout: () => 0, console };
runtime.window = runtime;
vm.runInNewContext(fs.readFileSync(require.resolve('../app.js'), 'utf8'), runtime, { filename: 'app.js' });
assert(elements.preview.textContent.includes('record_id'), 'browser startup populates the log preview');
assert.match(elements.seed.value, /^RV-[0-9a-f]{32}$/, 'browser startup creates a random private trainer seed');
assert.equal(elements['row-count'].textContent, '20', 'browser startup updates the row summary');
elements['download-logs'].dispatch('click');
assert.equal(blobs.length, 1, 'analyst JSONL click creates a downloadable Blob');
assert.equal(blobs[0].type, 'application/x-ndjson;charset=utf-8', 'analyst download has JSONL media type');
elements['download-raw'].dispatch('click');
assert.equal(blobs.length, 2, 'raw syslog click creates a downloadable Blob');
elements['download-key'].dispatch('click');
assert.equal(blobs.length, 3, 'answer-key click creates a separate downloadable Blob');
assert.equal(elements['answer-key'].textContent.length, 0, 'answer key is not exposed until the details panel is opened');

// Without Web Crypto, startup and pure generation must fail closed rather than downgrade randomness.
const noCryptoElements = Object.fromEntries(elementIds.map((id) => [id, new FakeElement(id)]));
Object.assign(noCryptoElements.family, { value: 'linux-messages' });
Object.assign(noCryptoElements['total-rows'], { value: '20' });
Object.assign(noCryptoElements['base-positives'], { value: '2' });
Object.assign(noCryptoElements.difficulty, { value: '2' });
const noCryptoDocument = { readyState: 'complete', body: new FakeElement('body'), getElementById: (id) => noCryptoElements[id] || null, createElement: (tag) => new FakeElement(tag) };
const noCryptoRuntime = { document: noCryptoDocument, window: null, Blob: runtime.Blob, URL: runtime.URL, setTimeout: runtime.setTimeout, console };
noCryptoRuntime.window = noCryptoRuntime;
vm.runInNewContext(fs.readFileSync(require.resolve('../app.js'), 'utf8'), noCryptoRuntime, { filename: 'app-no-crypto.js' });
assert.match(noCryptoElements.status.textContent, /secure randomness.*Web Crypto/i, 'browser reports unavailable secure randomness clearly');
assert.throws(() => noCryptoRuntime.SocLogLab.makeDataset({ ...base, seed: 'explicit-seed' }), /secure randomness.*Web Crypto/i, 'generation does not downgrade when secure randomness is unavailable');
console.log('SOC Log Lab pure-function and browser-runtime tests: PASS');

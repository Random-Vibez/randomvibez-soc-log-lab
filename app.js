(function (root) {
  'use strict';

  const FAMILY = Object.freeze({
    'linux-messages': { label: 'Linux messages / auth.log', kind: 'linux', raw: true },
    'linux-syslog': { label: 'Linux syslog', kind: 'linux', raw: true },
    'linux-maillog': { label: 'Linux maillog', kind: 'mail', raw: true },
    crowdstrike: { label: 'CrowdStrike CPS/ECS-inspired training JSON', kind: 'crowdstrike', raw: false },
    sentinel: { label: 'Microsoft Sentinel Syslog-table-shaped training JSON', kind: 'sentinel', raw: false },
    rapid7: { label: 'Rapid7 generic-syslog training JSON', kind: 'rapid7', raw: false }
  });
  const HOSTS = ['lab-node-01.example.test', 'lab-node-02.example.test', 'lab-mail-01.example.test'];
  const ACTORS = ['demo-analyst', 'lab-service', 'training-user', 'mail-demo'];
  const SCENARIOS = [
    { title: 'Authentication sequence worth reviewing', signal: 'Repeated failed SSH authentication is followed by a successful session from the same documentation-only source address.', events: ['sshd[4102]: Failed password for training-user from 192.0.2.44 port 41022 ssh2', 'sshd[4103]: Failed password for training-user from 192.0.2.44 port 41023 ssh2', 'sshd[4104]: Accepted publickey for training-user from 192.0.2.44 port 41024 ssh2'] },
    { title: 'Privilege change outside the expected sequence', signal: 'A synthetic account receives a privilege-change event after an unusual access sequence; review the linked records together.', events: ['sshd[5201]: Accepted publickey for lab-service from 198.51.100.27 port 41120 ssh2', 'sudo[5202]: training-user : TTY=pts/1 ; USER=root ; COMMAND=systemctl status demo-agent', 'audit[5203]: USER_CMD training-user requested a simulated privileged operation'] },
    { title: 'Service configuration sequence', signal: 'Several low-severity service events share the same host and service; their order is more informative than any single row.', events: ['systemd[6101]: Reloading demo-agent.service', 'systemd[6102]: Started demo-agent.service', 'audit[6103]: training change recorded for demo-agent.service; no executable payload'] },
    { title: 'Unexpected mail-queue pattern', signal: 'A synthetic mail service reports an unusual queue burst and a matching policy warning; recipients use reserved example domains.', events: ['postfix/smtpd[7201]: connect from relay.example.test[203.0.113.19]', 'postfix/qmgr[7202]: 3 synthetic messages entered the training queue for analyst@example.test', 'postfix/smtpd[7203]: policy review flagged a lab-only mail burst; no message was delivered'] },
    { title: 'Correlated access and outbound telemetry', signal: 'An access event and a later network observation share a synthetic host and source address; the destination uses a reserved documentation address.', events: ['sshd[8301]: Accepted publickey for demo-analyst from 192.0.2.44 port 41200 ssh2', 'kernel: lab firewall recorded a simulated outbound connection to 203.0.113.19:443', 'audit[8303]: synthetic review marker for the same lab host and source; no data transfer occurred'] }
  ];
  const MAIL_SCENARIOS = [
    { title: 'Mail queue pattern worth reviewing', signal: 'A synthetic mail queue burst is followed by a lab policy warning; every recipient uses a reserved example domain.', events: ['postfix/smtpd[7201]: connect from relay.example.test[203.0.113.19]', 'postfix/qmgr[7202]: 3 synthetic messages entered the training queue for analyst@example.test', 'postfix/smtpd[7203]: policy review flagged a lab-only mail burst; no message was delivered'] },
    { title: 'Mail authentication sequence', signal: 'A simulated mail authentication failure and later success share a synthetic source address and account; no password or token is recorded.', events: ['dovecot[7301]: auth failed for mail-demo from 198.51.100.27; no credential value logged', 'dovecot[7302]: auth succeeded for mail-demo from 198.51.100.27 using synthetic lab identity', 'postfix/submission[7303]: accepted synthetic message for recipient@example.test; delivery disabled'] },
    { title: 'Correlated mail transport notice', signal: 'A relay connection, queue record, and local policy notice form one synthetic sequence; check their order and shared source.', events: ['postfix/smtpd[7401]: connect from relay.example.test[192.0.2.44]', 'postfix/cleanup[7402]: message-id=<training-74@example.test> tagged for review', 'postfix/qmgr[7403]: synthetic queue entry held locally; no external delivery'] }
  ];
  const BENIGN = [
    'systemd[301]: Started demo-cache.service',
    'CRON[302]: (demo-analyst) CMD (scheduled training health check completed)',
    'sshd[303]: Accepted publickey for demo-analyst from 192.0.2.10 port 40100 ssh2',
    'kernel: lab firewall allowed a simulated connection to 198.51.100.8:443',
    'postfix/qmgr[304]: 1 synthetic message removed from the local training queue',
    'sudo[305]: demo-analyst : TTY=pts/0 ; USER=root ; COMMAND=systemctl status demo-cache',
    'systemd[306]: Stopped demo-cache.service (scheduled training maintenance)',
    'sshd[307]: Failed password for invalid user sample from 203.0.113.4 port 40101 ssh2'
  ];
  const MAIL_BENIGN = [
    'postfix/qmgr[304]: 1 synthetic message removed from the local training queue',
    'postfix/smtpd[305]: connection from relay.example.test[192.0.2.10] accepted for local training',
    'dovecot[306]: mail-demo closed a synthetic session; no message body stored',
    'postfix/cleanup[307]: local training message tagged with a reserved example address'
  ];

  function clampInt(value, min, max, name) {
    const number = Number(value);
    if (!Number.isInteger(number) || number < min || number > max) throw new RangeError(`${name} must be an integer from ${min} to ${max}.`);
    return number;
  }

  function normalizeConfig(config) {
    const family = String(config.family || 'linux-messages');
    if (!FAMILY[family]) throw new RangeError('Choose a supported log family.');
    const totalRows = clampInt(config.totalRows, 20, 2000, 'Total rows');
    const basePositives = clampInt(config.basePositives, 0, 100, 'Base positive detections');
    const difficulty = clampInt(config.difficulty, 1, 5, 'Difficulty');
    const seed = String(config.seed == null ? '' : config.seed).trim().slice(0, 64) || createSeed();
    return { family, totalRows, basePositives, difficulty, seed };
  }

  function secureRandomBytes(length) {
    if (!root.crypto || typeof root.crypto.getRandomValues !== 'function') {
      throw new Error('Secure randomness unavailable: this browser requires Web Crypto getRandomValues.');
    }
    const bytes = new Uint8Array(length);
    try {
      root.crypto.getRandomValues(bytes);
    } catch (error) {
      throw new Error('Secure randomness unavailable: Web Crypto getRandomValues failed.');
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function createRecordIds(count) {
    const ids = [];
    const unique = new Set();
    while (ids.length < count) {
      const id = `SYN-${bytesToHex(secureRandomBytes(16))}`;
      if (unique.has(id)) continue;
      unique.add(id);
      ids.push(id);
    }
    return ids;
  }

  function createProcessIds(count) {
    const ids = [];
    const unique = new Set();
    while (ids.length < count) {
      const bytes = secureRandomBytes(4);
      const value = ((bytes[0] * 0x1000000) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]) >>> 0;
      const pid = String(1 + (value % 2147483647));
      if (unique.has(pid)) continue;
      unique.add(pid);
      ids.push(pid);
    }
    return ids;
  }

  function hashSeed(seed) {
    let hash = 2166136261;
    for (let i = 0; i < seed.length; i += 1) {
      hash ^= seed.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return hash >>> 0;
  }

  function randomFromSeed(seed) {
    let state = hashSeed(seed) || 1;
    return function next() {
      state += 0x6D2B79F5;
      let value = state;
      value = Math.imul(value ^ (value >>> 15), value | 1);
      value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
      return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
    };
  }

  function timeAt(index) {
    const start = Date.UTC(2025, 0, 15, 9, 0, 0);
    return new Date(start + index * 47000).toISOString();
  }

  function syslogLine(row) {
    const severityNumber = row.outcome === 'failure' ? 4 : 6;
    const pri = row.facilityCode * 8 + severityNumber;
    const time = row.timestamp.replace(/\.\d{3}Z$/, 'Z');
    const host = row.host.replace(/\.example\.test$/, '');
    const app = row.process.slice(0, 48);
    return `<${pri}>1 ${time} ${host} ${app} ${row.pid} ${row.eventCode} - ${row.message} [training_record_id=${row.id}]`;
  }

  function classifyEvent(process, message) {
    const program = String(process).toLowerCase();
    const text = String(message).toLowerCase();
    let category = 'host';
    if (/^(sshd|dovecot)$/.test(program)) category = 'authentication';
    else if (/^(sudo|audit)$/.test(program)) category = 'iam';
    else if (program.startsWith('postfix')) category = 'email';
    else if (program === 'kernel') category = 'network';
    let facility = 'daemon';
    let facilityCode = 3;
    if (program === 'kernel') { facility = 'kern'; facilityCode = 0; }
    else if (program.startsWith('postfix') || program === 'dovecot') { facility = 'mail'; facilityCode = 2; }
    else if (program === 'cron') { facility = 'cron'; facilityCode = 9; }
    else if (/^(sshd|sudo|audit)$/.test(program)) { facility = 'authpriv'; facilityCode = 10; }
    let outcome = null;
    if (/failed password|auth failed|authentication rejected|\brejected\b/.test(text)) outcome = 'failure';
    else if (/accepted publickey|auth succeeded|started [a-z0-9_.-]+\.service|stopped [a-z0-9_.-]+\.service|allowed a simulated|removed from the local training queue|accepted for local training|entered the training queue/.test(text)) outcome = 'success';
    let action = 'log_event';
    if (category === 'authentication') action = outcome === 'failure' ? 'authentication_failure' : outcome === 'success' ? 'authentication_success' : 'authentication_event';
    else if (category === 'iam') action = 'privilege_activity';
    else if (category === 'email') action = 'mail_transport_or_queue_event';
    else if (category === 'network') action = 'network_observation';
    else if (category === 'host') action = 'host_service_event';
    let type = 'info';
    if (category === 'authentication' && outcome === 'failure') type = 'denied';
    else if (category === 'authentication' && outcome === 'success') type = 'allowed';
    else if (category === 'host' && /started .*\.service/.test(text)) type = 'start';
    return { category, outcome, action, type, severity: outcome === 'failure' ? 'Warning' : 'Informational', eventSeverity: outcome === 'failure' ? 55 : 30, facility, facilityCode };
  }

  function processName(message) {
    const match = /^([A-Za-z0-9_.\/-]+)(?:\[\d+\]|:)/.exec(String(message));
    return match ? match[1] : 'training';
  }

  function sourceIpFromMessage(message) {
    const text = String(message);
    const direct = /\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/i.exec(text);
    if (direct) return direct[1];
    const relay = /\b(?:connect|connection)\s+from\s+[^[]+\[((?:\d{1,3}\.){3}\d{1,3})\]/i.exec(text);
    return relay ? relay[1] : null;
  }

  function assignProcessId(message, generatedPid) {
    const text = String(message);
    const open = text.indexOf('[');
    const close = text.indexOf(']');
    const colon = text.indexOf(':');
    if (open <= 0 || close <= open || (colon >= 0 && colon < close)) return { message: text, pid: '-' };
    const sourcePid = text.slice(open + 1, close);
    const numericPid = sourcePid.length > 0 && [...sourcePid].every((character) => character >= '0' && character <= '9');
    if (!numericPid) return { message: text, pid: '-' };
    const process = text.slice(0, open);
    return { message: `${process}[${generatedPid}]${text.slice(close + 1)}`, pid: String(generatedPid) };
  }

  function shapedRecord(row, family) {
    if (family === 'sentinel') {
      return {
        TimeGenerated: row.timestamp, EventTime: row.timestamp, Computer: row.host,
        HostName: row.host, Facility: row.facility, ProcessID: row.pid === '-' ? null : Number(row.pid),
        ProcessName: row.process, SeverityLevel: row.severity, SyslogMessage: row.message,
        TrainingRecordId: row.id, TrainingOnly: true
      };
    }
    if (family === 'crowdstrike') {
      return {
        '@timestamp': row.timestamp, 'Cps.version': '1.0.0', 'ecs.version': '8.11.0',
        Vendor: 'TrainingExample', 'event.kind': 'event', 'event.category': [row.category],
        'event.type': [row.type], 'event.action': row.action,
        'event.outcome': row.outcome, 'event.severity': row.eventSeverity, 'event.id': row.id,
        'host.hostname': row.host, 'user.name': row.actor, 'source.ip': row.sourceIp,
        'process.name': row.process, 'event.original': row.message, 'TrainingOnly': true
      };
    }
    return {
      time: row.timestamp, source: 'generic_syslog_training', host: row.host,
      source_ip: row.sourceIp, program: row.process, severity: row.severity,
      message: row.message, record_id: row.id, TrainingOnly: true
    };
  }

  function makeDataset(input) {
    const config = normalizeConfig(input);
    const random = randomFromSeed(config.seed);
    const expectedFindings = Math.min(config.totalRows, config.basePositives + config.difficulty - 1);
    const supportBudget = Math.min((config.difficulty - 1) * expectedFindings, Math.max(0, config.totalRows - expectedFindings));
    const supportPerFinding = expectedFindings ? Math.floor(supportBudget / expectedFindings) : 0;
    const supportRemainder = expectedFindings ? supportBudget % expectedFindings : 0;
    const internalRows = [];
    const findings = [];
    const generatedIds = createRecordIds(config.totalRows);
    const generatedProcessIds = createProcessIds(config.totalRows);
    const rowId = (index) => generatedIds[index];

    for (let findingIndex = 0; findingIndex < expectedFindings; findingIndex += 1) {
      const scenarios = config.family === 'linux-maillog' ? MAIL_SCENARIOS : SCENARIOS;
      const scenario = scenarios[findingIndex % scenarios.length];
      const count = 1 + supportPerFinding + (findingIndex < supportRemainder ? 1 : 0);
      const rowIds = [];
      const evidenceMessages = [];
      for (let eventIndex = 0; eventIndex < count; eventIndex += 1) {
        const id = rowId(internalRows.length);
        rowIds.push(id);
        let message = scenario.events[eventIndex % scenario.events.length];
        if (config.difficulty >= 4 && eventIndex === 0) message = message.replace('Failed password', 'authentication rejected').replace('policy review flagged', 'policy review marker recorded').replace('auth failed', 'authentication rejected');
        const assigned = assignProcessId(message, generatedProcessIds[internalRows.length]);
        message = assigned.message;
        evidenceMessages.push(message);
        internalRows.push({
          id, timestamp: null,
          host: HOSTS[findingIndex % HOSTS.length], actor: ACTORS[findingIndex % ACTORS.length],
          sourceIp: sourceIpFromMessage(message), process: processName(message),
          pid: assigned.pid, eventCode: 'SYNTH',
          facility: 'authpriv', ...classifyEvent(processName(message), message), message,
          isPositive: eventIndex === 0, findingIndex
        });
      }
      findings.push({
        id: `F-${String(findingIndex + 1).padStart(3, '0')}`,
        title: scenario.title, rowIds,
        analystNote: count === 1
          ? `Single-row training signal: ${evidenceMessages[0]}`
          : `This finding contains ${count} emitted linked rows. Compare the exact messages and row IDs in the evidence list; no unstated events are part of this key.`,
        explanation: `Planted training finding ${findingIndex + 1}. The key lists exactly ${count} emitted row IDs and their messages; no extra sequence event is implied. No real credentials, malware, or external indicators are present.`,
        evidence: rowIds.map((recordId, index) => ({ recordId, message: evidenceMessages[index] }))
      });
    }

    while (internalRows.length < config.totalRows) {
      const index = internalRows.length;
      const benignEvents = config.family === 'linux-maillog' ? MAIL_BENIGN : BENIGN;
      const message = benignEvents[Math.floor(random() * benignEvents.length)];
      const assigned = assignProcessId(message, generatedProcessIds[index]);
      const normalizedMessage = assigned.message;
      internalRows.push({
        id: rowId(index), timestamp: null, host: HOSTS[Math.floor(random() * HOSTS.length)],
        actor: ACTORS[Math.floor(random() * ACTORS.length)], sourceIp: sourceIpFromMessage(normalizedMessage),
        process: processName(normalizedMessage), pid: assigned.pid,
        eventCode: 'SYNTH', facility: 'authpriv', ...classifyEvent(processName(normalizedMessage), normalizedMessage), message: normalizedMessage,
        isPositive: false, findingIndex: null
      });
    }

    for (let i = internalRows.length - 1; i > 0; i -= 1) {
      const swap = Math.floor(random() * (i + 1));
      [internalRows[i], internalRows[swap]] = [internalRows[swap], internalRows[i]];
    }
    // Assign timestamps after the emission shuffle so sorting by time cannot recover the
    // planted-construction block. Then restore chronology only within each finding.
    const timeline = [];
    for (let index = 0; index < internalRows.length; index += 1) timeline.push(timeAt(index));
    for (let i = timeline.length - 1; i > 0; i -= 1) {
      const swap = Math.floor(random() * (i + 1));
      [timeline[i], timeline[swap]] = [timeline[swap], timeline[i]];
    }
    for (let index = 0; index < internalRows.length; index += 1) {
      internalRows[index].timestamp = timeline[index];
    }
    for (const finding of findings) {
      if (finding.rowIds.length <= 1) continue;
      const linkedRows = finding.rowIds.map((recordId) => {
        const row = internalRows.find((candidate) => candidate.id === recordId);
        if (!row) throw new Error("Planted finding references a missing row.");
        return row;
      });
      const orderedTimes = linkedRows.map((row) => row.timestamp).slice().sort();
      for (let index = 0; index < linkedRows.length; index += 1) {
        linkedRows[index].timestamp = orderedTimes[index];
      }
    }
    const meta = FAMILY[config.family];
    const logs = internalRows.map((row) => meta.kind === 'linux' || meta.kind === 'mail'
      ? { timestamp: row.timestamp, host: row.host, process: row.process, message: row.message, severity: row.severity, facility: row.facility, facility_code: row.facilityCode, process_id: row.pid, source_ip: row.sourceIp, record_id: row.id }
      : shapedRecord(row, config.family));
    const rawSyslog = meta.raw ? internalRows.map(syslogLine).join('\n') + '\n' : null;
    const answerKey = {
      trainingOnly: true,
      seed: config.seed,
      family: config.family,
      summary: { totalRows: config.totalRows, basePositiveDetections: config.basePositives, difficulty: config.difficulty, plantedFindings: findings.length },
      findings: findings.map((finding) => ({ ...finding }))
    };
    return { config, logs, findings: answerKey.findings, answerKey, rawSyslog };
  }

  function jsonLines(dataset) {
    return dataset.logs.map((row) => JSON.stringify(row)).join('\n') + '\n';
  }

  function createSeed() {
    return `RV-${bytesToHex(secureRandomBytes(16))}`;
  }

  const api = Object.freeze({ FAMILY, normalizeConfig, hashSeed, makeDataset, jsonLines, createSeed });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root && root.window === root) {
    root.SocLogLab = api;
    const init = () => {
      const form = root.document.getElementById('generator');
      if (!form) return;
      const seed = root.document.getElementById('seed');
      const preview = root.document.getElementById('preview');
      const status = root.document.getElementById('status');
      const keyPanel = root.document.getElementById('show-key');
      const rawButton = root.document.getElementById('download-raw');
      const logsButton = root.document.getElementById('download-logs');
      const keyButton = root.document.getElementById('download-key');
      let current = null;

      function failGeneration(error) {
        current = null;
        status.textContent = error.message;
        preview.textContent = '';
        rawButton.disabled = true;
        logsButton.disabled = true;
        keyButton.disabled = true;
      }

      function inputs() {
        return { family: root.document.getElementById('family').value,
          totalRows: root.document.getElementById('total-rows').value,
          basePositives: root.document.getElementById('base-positives').value,
          difficulty: root.document.getElementById('difficulty').value, seed: seed.value };
      }
      function refresh() {
        try {
          if (!seed.value.trim()) seed.value = createSeed();
          current = makeDataset(inputs());
          const extra = current.config.difficulty - 1;
          root.document.getElementById('finding-count').textContent = String(current.findings.length);
          root.document.getElementById('extra-count').textContent = String(Math.min(extra, Math.max(0, current.config.totalRows - current.config.basePositives)));
          root.document.getElementById('row-count').textContent = String(current.logs.length);
          root.document.getElementById('seed-label').textContent = current.config.seed;
          root.document.getElementById('difficulty-description').textContent = [
            'One event per planted finding; signals are direct.',
            'Adds one finding and begins linked-event context.',
            'Adds a finding and more correlated supporting events.',
            'Adds a finding with quieter, less explicit wording.',
            'Adds a finding with the most cross-event correlation and subtle cues.'
          ][current.config.difficulty - 1];
          preview.textContent = current.logs.slice(0, 8).map((row) => JSON.stringify(row)).join('\n');
          root.document.getElementById('preview-note').textContent = `Previewing 8 of ${current.logs.length} analyst rows. The answer key is a separate download.`;
          rawButton.disabled = !current.rawSyslog;
          logsButton.disabled = false;
          keyButton.disabled = false;
          if (keyPanel.open) showKey();
          status.textContent = 'Preview updated. The same settings and trainer seed reproduce scenario content and order; record IDs are fresh for each generation.';
        } catch (error) {
          failGeneration(error);
        }
      }
      function download(name, content, type) {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const link = root.document.createElement('a');
        link.href = url; link.download = name; link.hidden = true;
        root.document.body.appendChild(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      function showKey() {
        if (!current) return;
        const target = root.document.getElementById('answer-key');
        target.textContent = JSON.stringify(current.answerKey, null, 2);
      }
      form.addEventListener('input', refresh);
      form.addEventListener('change', refresh);
      root.document.getElementById('new-seed').addEventListener('click', () => {
        try { seed.value = createSeed(); refresh(); } catch (error) { failGeneration(error); }
      });
      root.document.getElementById('download-logs').addEventListener('click', () => {
        if (!current) return;
        download('soc-log-lab-analyst.jsonl', jsonLines(current), 'application/x-ndjson;charset=utf-8');
      });
      rawButton.addEventListener('click', () => {
        if (current && current.rawSyslog) download(`soc-log-lab-${current.config.family}.log`, current.rawSyslog, 'text/plain;charset=utf-8');
      });
      root.document.getElementById('download-key').addEventListener('click', () => {
        if (current) download('soc-log-lab-answer-key.json', JSON.stringify(current.answerKey, null, 2) + '\n', 'application/json;charset=utf-8');
      });
      root.document.getElementById('show-key').addEventListener('toggle', (event) => { if (event.target.open) showKey(); });
      try {
        seed.value = seed.value.trim() || createSeed();
        refresh();
      } catch (error) {
        failGeneration(error);
      }
    };
    const noticeSlot = root.document.getElementById('cookie-notice-slot');
    if (noticeSlot && root.MutationObserver) {
      const observer = new root.MutationObserver(() => {
        const notice = root.document.querySelector('.cookie-banner');
        if (!notice) return;
        noticeSlot.appendChild(notice);
        observer.disconnect();
      });
      observer.observe(root.document.body, { childList: true });
      const notice = root.document.querySelector('.cookie-banner');
      if (notice) {
        noticeSlot.appendChild(notice);
        observer.disconnect();
      }
    }
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', init, { once: true });
    else init();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);

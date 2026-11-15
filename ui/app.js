const state = {
  data: null,
  activeJob: false
};

const els = {
  benignCompletion: document.getElementById('benignCompletion'),
  seenLeak: document.getElementById('seenLeak'),
  unseenLeak: document.getElementById('unseenLeak'),
  attrF1: document.getElementById('attrF1'),
  defenseTable: document.getElementById('defenseTable'),
  scenarioList: document.getElementById('scenarioList'),
  defenseChart: document.getElementById('defenseChart'),
  dataStatus: document.getElementById('dataStatus'),
  terminalOutput: document.getElementById('terminalOutput'),
  refreshBtn: document.getElementById('refreshBtn'),
  runEvalBtn: document.getElementById('runEvalBtn'),
  runDemoBtn: document.getElementById('runDemoBtn'),
  viewResultsBtn: document.getElementById('viewResultsBtn'),
  explainScenario: document.getElementById('explainScenario'),
  explainBtn: document.getElementById('explainBtn'),
  explainStatus: document.getElementById('explainStatus'),
  explainSummary: document.getElementById('explainSummary'),
  explainEvents: document.getElementById('explainEvents'),
  riskDetails: document.getElementById('riskDetails'),
  counterfactualPanel: document.getElementById('counterfactualPanel')
};

const actionButtons = [els.refreshBtn, els.runEvalBtn, els.runDemoBtn, els.viewResultsBtn];

function formatPercent(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '--';
  return `${Number(value).toFixed(1)}%`;
}

function formatScore(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '--';
  return Number(value).toFixed(2);
}

function getSentinelMetrics(data) {
  return data['CollusionGuard (ours)'];
}

function renderMetrics(data) {
  const metrics = getSentinelMetrics(data);
  if (!metrics) throw new Error('Multiagent Sentinel metrics are missing from results.json.');
  els.benignCompletion.textContent = formatPercent(metrics.benign_completion);
  els.seenLeak.textContent = formatPercent(metrics.seen_leak_prevented);
  els.unseenLeak.textContent = formatPercent(metrics.unseen_leak_prevented);
  els.attrF1.textContent = formatScore(metrics.attribution_f1);
}

function renderDefenseRows(data) {
  const rows = Object.entries(data).filter(([, metrics]) =>
    metrics && typeof metrics.seen_leak_prevented !== 'undefined'
  );
  els.defenseTable.innerHTML = rows.map(([name, metrics]) => `
    <tr>
      <td>${displayDefenseName(name)}</td>
      <td>${formatPercent(metrics.seen_leak_prevented)}</td>
      <td>${formatPercent(metrics.unseen_leak_prevented)}</td>
      <td>${formatPercent(metrics.benign_false_block)}</td>
    </tr>
  `).join('');
  renderDefenseChart(rows);
}

function displayDefenseName(name) {
  const labels = {
    'Ours: binary (no grading)': 'Sentinel (binary, no grading)',
    'CollusionGuard (ours)': 'Multiagent Sentinel',
    'CollusionGuard + content scan': 'Sentinel + content scan'
  };
  return labels[name] || name;
}

function smoothPath(points) {
  if (!points.length) return '';
  if (points.length === 1) return `M ${points[0].x} ${points[0].y}`;
  let path = `M ${points[0].x} ${points[0].y}`;
  for (let i = 0; i < points.length - 1; i += 1) {
    const previous = points[Math.max(0, i - 1)];
    const current = points[i];
    const next = points[i + 1];
    const following = points[Math.min(points.length - 1, i + 2)];
    const c1x = current.x + (next.x - previous.x) / 6;
    const minY = Math.min(current.y, next.y);
    const maxY = Math.max(current.y, next.y);
    const c1y = Math.max(minY, Math.min(maxY, current.y + (next.y - previous.y) / 6));
    const c2x = next.x - (following.x - current.x) / 6;
    const c2y = Math.max(minY, Math.min(maxY, next.y - (following.y - current.y) / 6));
    path += ` C ${c1x} ${c1y}, ${c2x} ${c2y}, ${next.x} ${next.y}`;
  }
  return path;
}

function renderDefenseChart(rows) {
  if (!rows.length) {
    els.defenseChart.innerHTML = '<div class="chart-empty">Run the evaluation to load chart data.</div>';
    return;
  }

  const width = 400;
  const height = 166;
  const left = 34;
  const right = 12;
  const top = 8;
  const bottom = 34;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const x = (index) => rows.length === 1 ? left + plotWidth / 2 : left + index * plotWidth / (rows.length - 1);
  const y = (value) => top + (100 - Math.max(0, Math.min(100, Number(value) || 0))) * plotHeight / 100;
  const series = [
    { key: 'seen_leak_prevented', lineClass: 'seen-line', pointClass: 'seen-point' },
    { key: 'unseen_leak_prevented', lineClass: 'unseen-line', pointClass: 'unseen-point' }
  ];

  const grid = [0, 25, 50, 75, 100].map((value) => {
    const pointY = y(value);
    return `
      <line class="chart-grid" x1="${left}" y1="${pointY}" x2="${width - right}" y2="${pointY}"></line>
      <text class="chart-axis-label" x="${left - 7}" y="${pointY + 3}" text-anchor="end">${value}</text>
    `;
  }).join('');

  const lines = series.map(({ key, lineClass, pointClass }) => {
    const points = rows.map(([, metrics], index) => ({ x: x(index), y: y(metrics[key]) }));
    return `
      <path class="chart-line ${lineClass}" d="${smoothPath(points)}"></path>
      ${points.map((point) => `<circle class="chart-point ${pointClass}" cx="${point.x}" cy="${point.y}" r="3.3"></circle>`).join('')}
    `;
  }).join('');

  const labels = rows.map(([name], index) => {
    const shortNames = {
      'No defence': 'None',
      'Per-agent monitor': 'Agent',
      'Signature DLP': 'DLP',
      'Block-all-suspicious': 'Strict',
      'Ours: binary (no grading)': 'Binary',
      'CollusionGuard (ours)': 'Sentinel',
      'CollusionGuard + content scan': 'Sentinel+scan'
    };
    const shortName = shortNames[name] || name;
    return `<text class="chart-x-label" x="${x(index)}" y="${height - 8}" text-anchor="middle">${shortName}</text>`;
  }).join('');

  els.defenseChart.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Seen and unseen leak prevention rates for each defense">
      ${grid}
      ${lines}
      ${labels}
    </svg>
  `;
}

function renderScenarios(data) {
  const metrics = getSentinelMetrics(data);
  const scenarios = metrics && metrics.per_kind ? Object.entries(metrics.per_kind) : [];
  if (!scenarios.length) {
    els.scenarioList.innerHTML = '<div class="chart-empty">Scenario data is unavailable.</div>';
    return;
  }

  els.scenarioList.innerHTML = scenarios.map(([kind, result]) => {
    const status = result.leaked > 0 ? 'alert' : result.detected > 0 ? 'watch' : 'safe';
    const label = status === 'alert' ? 'LEAK' : status === 'watch' ? 'FLAG' : 'SAFE';
    return `
      <div class="scenario-item">
        <div class="scenario-meta">
          <strong>${kind}</strong>
          <span>Detected: ${formatPercent(result.detected)} · Leak: ${formatPercent(result.leaked)}</span>
        </div>
        <span class="badge ${status}">${label}</span>
      </div>
    `;
  }).join('');
}

async function loadResults({ updateLog = true } = {}) {
  els.dataStatus.textContent = 'SYNCING';
  try {
    const response = await fetch('/api/results', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Results request failed (${response.status}).`);
    renderMetrics(data);
    renderDefenseRows(data);
    renderScenarios(data);
    state.data = data;
    els.dataStatus.textContent = 'SYNCED';
    if (updateLog) {
      els.terminalOutput.textContent = `Loaded current results.json from the project backend.\n${Object.keys(data).filter((key) => !key.startsWith('_')).length} defense strategies available.`;
    }
  } catch (error) {
    els.dataStatus.textContent = 'OFFLINE';
    if (updateLog) els.terminalOutput.textContent = `Could not load backend results: ${error.message}`;
  }
}

function setBusy(isBusy) {
  state.activeJob = isBusy;
  actionButtons.forEach((button) => {
    button.disabled = isBusy;
    button.setAttribute('aria-busy', String(isBusy));
  });
}

const delay = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function agentName(agent) {
  return ({
    P: 'Planner', R: 'Researcher', A: 'Analyst', W: 'Writer', N: 'Notifier',
    MEM: 'Shared memory', EXTERNAL: 'External'
  })[agent] || agent || '—';
}

function eventTarget(event) {
  return event.sink !== 'none' ? event.sink : event.dst;
}

function formatFactorValue(value, digits = 2) {
  return Number.isFinite(Number(value)) ? Number(value).toFixed(digits) : '0.00';
}

function renderExplainSummary(data) {
  const outcome = data.leaked
    ? '<span class="outcome-badge danger">Sensitive data leaked</span>'
    : data.suspended
      ? '<span class="outcome-badge warning">Workflow suspended</span>'
      : '<span class="outcome-badge success">No sensitive data leaked</span>';
  els.explainSummary.innerHTML = `
    <div><strong>${escapeHtml(data.scenario_label)}</strong><span>Seed ${data.seed} · scripted simulation</span></div>
    ${outcome}
  `;
}

function renderExplainEvents(data, selectedId) {
  els.explainEvents.innerHTML = data.events.map((event) => {
    const selected = event.eid === selectedId ? ' selected' : '';
    const labels = event.labels.length ? event.labels.join(', ') : 'unlabelled';
    const decision = event.decision === 'allow' ? 'allow' : event.decision;
    return `
      <button type="button" class="explain-event${selected}" data-event-id="${event.eid}" aria-pressed="${event.eid === selectedId}">
        <span class="event-topline"><strong>#${event.eid} ${escapeHtml(event.step)}</strong><span class="event-risk ${escapeHtml(event.tier.toLowerCase())}">${escapeHtml(event.tier)} · ${formatFactorValue(event.risk, 1)}</span></span>
        <span class="event-route">${escapeHtml(agentName(event.src))} → ${escapeHtml(agentName(eventTarget(event)))}</span>
        <span class="event-footline"><span>${escapeHtml(labels)}</span><span class="decision-label ${escapeHtml(decision)}">${escapeHtml(decision)}</span></span>
      </button>
    `;
  }).join('');
}

function renderRiskDetails(event) {
  if (!event) {
    els.riskDetails.innerHTML = '<h3>Risk breakdown</h3><p class="chart-empty">No event selected.</p>';
    return;
  }
  const factors = event.risk_factors || {};
  const parts = event.risk_parts || {};
  const sensitivity = factors.sensitivity || {};
  const destination = factors.destination || {};
  const permission = factors.permission_gap || {};
  const relay = factors.relay_length || {};
  const novelty = factors.novelty || {};
  const trust = factors.trust || {};
  const labels = sensitivity.labels && sensitivity.labels.length ? sensitivity.labels.join(', ') : 'No sensitivity label';
  const path = (relay.path || []).map(agentName).join(' → ') || 'No agent relay';
  const rows = [
    { name: 'Sensitivity', detail: `${labels} · severity ${formatFactorValue(sensitivity.severity)}`, value: '' },
    { name: 'Destination', detail: `${destination.sink || event.sink} sink · weight ${formatFactorValue(destination.weight)}`, value: `+${formatFactorValue(factors.sensitive_destination_contribution)}` },
    { name: 'Permission gap', detail: permission.missing && permission.missing.length ? `${agentName(permission.agent)} lacks ${permission.missing.join(', ')}` : 'No missing sensitivity permission', value: `+${formatFactorValue(permission.contribution)}` },
    { name: 'Relay length', detail: `${relay.agents || 0} agents · ${path}`, value: `+${formatFactorValue(relay.contribution)}` },
    { name: 'Novelty', detail: `Baseline novelty ${formatFactorValue(novelty.score)}`, value: `+${formatFactorValue(novelty.contribution)}` },
    { name: 'Trust', detail: `Minimum agent trust ${formatFactorValue(trust.minimum)}`, value: `+${formatFactorValue(trust.contribution)}` }
  ];
  els.riskDetails.innerHTML = `
    <h3>Risk breakdown</h3>
    <div class="risk-total"><span>Final score</span><strong>${formatFactorValue(event.risk, 1)} / 100 · ${escapeHtml(event.tier)}</strong></div>
    <p class="risk-formula">Sensitive-destination risk is the combined sensitivity × destination contribution; other values are additive score contributions. The total is capped at 100.</p>
    <div class="factor-list">${rows.map((row) => `
      <div class="factor-row">
        <span class="factor-marker ${row.value && Number(row.value.slice(1)) > 0 ? 'raised' : ''}"></span>
        <div><strong>${escapeHtml(row.name)}</strong><span>${escapeHtml(row.detail)}</span></div>
        <b>${escapeHtml(row.value)}</b>
      </div>
    `).join('')}</div>
    <div class="decision-reason"><strong>Decision: ${escapeHtml(event.decision)}</strong><span>${escapeHtml(event.reason || 'No additional rule explanation.')}</span></div>
  `;
}

function renderCounterfactual(data, event) {
  const explanation = data.explanations.find((item) => item.eid === event.eid);
  if (!explanation) {
    els.counterfactualPanel.innerHTML = `
      <h3>Counterfactual explanation</h3>
      <p class="chart-empty">${event.risk < 50
        ? 'No counterfactual is generated below the High-risk threshold. This action was handled using its risk tier.'
        : 'No counterfactual chain was recorded for this action.'}</p>
    `;
    return;
  }
  els.counterfactualPanel.innerHTML = `
    <h3>Counterfactual explanation · event #${explanation.eid}</h3>
    <p class="counterfactual-text">${escapeHtml(explanation.text)}</p>
    <p class="culprit-list"><strong>Likely necessary agents:</strong> ${explanation.culprits.map((agent) => escapeHtml(agentName(agent))).join(', ') || 'None identified'}</p>
    <ol class="causal-chain">${explanation.chain.map((step) => `
      <li><span>#${step.eid} · ${escapeHtml(step.step)}</span><strong>${escapeHtml(agentName(step.src))} → ${escapeHtml(agentName(step.sink !== 'none' ? (step.sink === 'external' ? 'EXTERNAL' : step.sink) : step.dst))}</strong></li>
    `).join('')}</ol>
  `;
}

function selectExplainEvent(eventId) {
  const data = state.explanation;
  if (!data) return;
  const event = data.events.find((item) => item.eid === eventId);
  if (!event) return;
  state.selectedExplainEvent = eventId;
  renderExplainEvents(data, eventId);
  renderRiskDetails(event);
  renderCounterfactual(data, event);
}

async function loadExplanation() {
  els.explainBtn.disabled = true;
  els.explainStatus.textContent = 'Running scenario…';
  els.explainSummary.textContent = 'Executing the scripted scenario and collecting risk evidence…';
  try {
    const response = await fetch('/api/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: els.explainScenario.value })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Explanation request failed (${response.status}).`);
    state.explanation = data;
    renderExplainSummary(data);
    const preferred = [...data.explanations].reverse().find((item) =>
      data.events.some((event) => event.eid === item.eid)
    );
    const selected = preferred ? preferred.eid : data.events[data.events.length - 1]?.eid;
    if (selected !== undefined) selectExplainEvent(selected);
    els.explainStatus.textContent = 'Complete';
  } catch (error) {
    state.explanation = null;
    els.explainStatus.textContent = 'Failed';
    els.explainSummary.textContent = `Could not load explanation: ${error.message}`;
    els.explainEvents.innerHTML = '<p class="chart-empty">The event trace could not be loaded.</p>';
    els.riskDetails.innerHTML = '<h3>Risk breakdown</h3><p class="chart-empty">No decision evidence available.</p>';
    els.counterfactualPanel.innerHTML = '<h3>Counterfactual explanation</h3><p class="chart-empty">No counterfactual evidence available.</p>';
  } finally {
    els.explainBtn.disabled = false;
  }
}

async function runAction(command) {
  if (state.activeJob) return;
  setBusy(true);
  els.terminalOutput.textContent = `Starting ${command === 'demo' ? 'demo' : 'evaluation'}...`;

  try {
    const response = await fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command })
    });
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || `Could not start command (${response.status}).`);

    els.terminalOutput.textContent = `Running ${command === 'demo' ? 'demo' : 'evaluation'}...`;
    while (true) {
      await delay(700);
      const statusResponse = await fetch(`/api/jobs/${encodeURIComponent(job.job_id)}`, { cache: 'no-store' });
      const status = await statusResponse.json();
      if (!statusResponse.ok) throw new Error(status.error || `Job status request failed (${statusResponse.status}).`);
      if (!status.done) continue;

      if (!status.success) throw new Error(status.error || 'The project command failed.');
      els.terminalOutput.textContent = status.output || 'Command completed successfully.';
      if (command === 'evaluate') await loadResults({ updateLog: false });
      break;
    }
  } catch (error) {
    els.terminalOutput.textContent = `Command failed: ${error.message}`;
  } finally {
    setBusy(false);
  }
}

els.refreshBtn.addEventListener('click', () => loadResults());
els.runEvalBtn.addEventListener('click', () => runAction('evaluate'));
els.runDemoBtn.addEventListener('click', () => runAction('demo'));
els.viewResultsBtn.addEventListener('click', () => {
  loadResults();
  document.getElementById('defenses').scrollIntoView({ behavior: 'smooth', block: 'center' });
});
els.explainBtn.addEventListener('click', loadExplanation);
els.explainEvents.addEventListener('click', (event) => {
  const button = event.target.closest('[data-event-id]');
  if (button) selectExplainEvent(Number(button.dataset.eventId));
});

loadResults();
loadExplanation();

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
  viewResultsBtn: document.getElementById('viewResultsBtn')
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

loadResults();

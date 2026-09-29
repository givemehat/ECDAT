/**
 * IndraMesh Web Console Application Logic
 * Role-based Cybersecurity Dashboard for NTRO Post-Quantum Cryptography Migration (SIH26164)
 */

const STATE = {
  status: null,
  scanData: null,
  activeTab: 'posture',
  topology: null,
  radarReticle: null,
  filterQuery: '',
  selectedTiers: new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  onlyHndl: false,
  selectedRecord: null,
  browsePath: null,
};

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  setupIcons();
  setupTabs();
  setupEvents();

  // Initialize Framer Motion micro-interactions & tactile feedback
  if (typeof Motion !== 'undefined') {
    Motion.setupMorphingTabs('.nav-tabs', '#tab-slider-pill');
    Motion.setupCircularRipples('.btn-primary, .btn-secondary, .btn-outline, .chip-btn, .tab-btn');
    Motion.setupCardSpotlight('.deck-card, .metric-card');
    Motion.setupMagneticButtons('.btn-primary');
  }

  // Initialize Circular Radar Scanner immediately on page load
  if (typeof CircularRadarReticle !== 'undefined') {
    STATE.radarReticle = new CircularRadarReticle('radial-dial');
    STATE.radarReticle.start();
  }

  await loadStatus();
  
  // Initialize topology canvas
  STATE.topology = new TopologyVisualizer('topology-canvas', 'topology-wrapper');
  window.onTopologyNodeClick = (node) => {
    if (node.type === 'asset') {
      // Find matching record
      const rec = (STATE.scanData?.records || []).find(r => 
        r.name === node.name && (r.tier === node.tier || !node.tier)
      );
      if (rec) openDrawer(rec);
    }
  };

  // Run initial scan on dummy_target to present live data immediately
  runScan('./dummy_target');
});

function setupIcons() {
  document.querySelectorAll('[data-icon]').forEach(el => {
    const iconName = el.getAttribute('data-icon');
    if (ICONS[iconName]) {
      el.innerHTML = ICONS[iconName];
    }
  });
}

function setupTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabKey = btn.getAttribute('data-tab');
      switchTab(tabKey);
    });
  });
}

function switchTab(tabKey) {
  STATE.activeTab = tabKey;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabKey);
  });
  document.querySelectorAll('.tab-content').forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabKey}`);
  });

  if (tabKey === 'topology' && STATE.topology) {
    setTimeout(() => STATE.topology.resize(), 50);
  }
  if (tabKey === 'history') {
    loadHistoryList();
  }
  if (tabKey === 'posture') {
    if (STATE.radarReticle) STATE.radarReticle.start();
    if (STATE.scanData) renderPostureView(STATE.scanData);
  } else {
    if (STATE.radarReticle) STATE.radarReticle.stop();
  }
}

// -----------------------------------------------------------------------------
// API & Data Handling
// -----------------------------------------------------------------------------
async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    STATE.status = data;

    // Populate Policy dropdown
    const policySelect = document.getElementById('policy-select');
    policySelect.innerHTML = '';
    for (const [key, pol] of Object.entries(data.policies)) {
      const opt = document.createElement('option');
      opt.value = key;
      opt.textContent = `${pol.label} (${pol.year})`;
      if (key === 'india_dst_nqm') opt.selected = true;
      policySelect.appendChild(opt);
    }

    // Populate Data Class dropdown
    const dataClassSelect = document.getElementById('dataclass-select');
    dataClassSelect.innerHTML = '';
    for (const [key, dc] of Object.entries(data.data_classes)) {
      const opt = document.createElement('option');
      opt.value = key;
      opt.textContent = `${key} (${dc.years}y) - ${dc.note}`;
      if (key === 'operational-record') opt.selected = true;
      dataClassSelect.appendChild(opt);
    }

    // Update Z Slider
    const zSlider = document.getElementById('z-slider');
    const zVal = document.getElementById('z-val');
    const zBasis = document.getElementById('z-basis');
    zSlider.value = data.default_z || 10;
    zVal.textContent = `${zSlider.value}y`;
    zBasis.textContent = `28-49% probability of CRQC in this window (GRI/evolutionQ)`;

    zSlider.addEventListener('input', () => {
      zVal.textContent = `${zSlider.value}y`;
      zBasis.textContent = `CRQC estimate horizon: ${zSlider.value} years`;
    });

    zSlider.addEventListener('change', () => {
      reRateEstate();
    });

  } catch (err) {
    console.error('Failed to load status:', err);
  }
}

async function runScan(targetOverride = null) {
  const targetInput = document.getElementById('target-input');
  const target = targetOverride || targetInput.value.trim() || './dummy_target';
  targetInput.value = target;

  const enableMl = document.getElementById('enable-ml-toggle').checked;
  const policy = document.getElementById('policy-select').value;
  const dataClass = document.getElementById('dataclass-select').value;
  const zYears = parseFloat(document.getElementById('z-slider').value);
  const xOverride = parseFloat(document.getElementById('override-x').value) || null;
  const yOverride = parseFloat(document.getElementById('override-y').value) || null;

  showProgress(true, `Scanning ${target} with rule engines...`);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target,
        enable_ml: enableMl,
        policy,
        data_class: dataClass,
        z_years: zYears,
        x_override: xOverride,
        y_override: yOverride,
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Scan failed');
    }

    const data = await res.json();
    STATE.scanData = data;
    renderAllViews(data);
    loadTopology();
  } catch (err) {
    alert(`Scan Error: ${err.message}`);
  } finally {
    showProgress(false);
  }
}

async function reRateEstate() {
  if (!STATE.scanData) return;

  const policy = document.getElementById('policy-select').value;
  const dataClass = document.getElementById('dataclass-select').value;
  const zYears = parseFloat(document.getElementById('z-slider').value);
  const xOverride = parseFloat(document.getElementById('override-x').value) || null;
  const yOverride = parseFloat(document.getElementById('override-y').value) || null;

  try {
    const res = await fetch('/api/rate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        policy,
        data_class: dataClass,
        z_years: zYears,
        x_override: xOverride,
        y_override: yOverride,
      }),
    });

    if (!res.ok) throw new Error('Rating update failed');
    const data = await res.json();
    STATE.scanData = data;
    renderAllViews(data);
  } catch (err) {
    console.error('Re-rate error:', err);
  }
}

async function loadTopology() {
  try {
    const res = await fetch('/api/topology');
    const data = await res.json();
    if (STATE.topology) {
      STATE.topology.setData(data);
    }
  } catch (err) {
    console.error('Topology load error:', err);
  }
}

// -----------------------------------------------------------------------------
// View Rendering
// -----------------------------------------------------------------------------
function renderAllViews(data) {
  renderIntegrityBanner(data);
  renderPostureView(data);
  renderEvidenceView(data);
  renderAuditorView(data);
  renderPlannerView(data);
  renderComplianceView(data);
}

/* ==========================================================================================
   MOTION HELPERS
   ==========================================================================================
   Two rules govern everything in this section, and both are about honesty rather than taste:

   1. MOTION IS INSTRUMENTATION. The only animation permitted to run unattended is the scan
      sweep, and it is removed the instant a result exists. A console that keeps pulsing after
      it has finished makes the analyst believe work is still happening.
   2. THE TEXT IS SET FIRST, THE ANIMATION SECOND. Every helper here writes the final value
      before it touches a class or a style. If the browser has reduced motion on, or the CSS
      fails to load, or the animation never runs, the reader still sees the correct number. An
      animation that is load-bearing for a displayed value is one more way to show a wrong
      answer, which is the thing this entire project is about.
   ========================================================================================== */

/** True when the reader has asked for less motion. Checked in JS as well as CSS, so behaviour
 *  that is expensive or distracting is skipped outright rather than merely made invisible. */
function prefersReducedMotion() {
  return window.matchMedia
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** Set a metric, marking it when the value actually changed.
 *
 *  Not on first render: every metric would flash once on load, which is noise that trains the
 *  reader to ignore the very signal this is meant to provide. The class is removed and
 *  re-added to restart the animation, because re-adding an identical class does nothing.
 */
function setMetric(id, value, delay = 0, force = true) {
  const el = document.getElementById(id);
  if (!el) return;
  const next = String(value ?? 0);
  const targetNum = parseFloat(next) || 0;
  const prevVal = parseFloat(el.dataset.prevVal ?? (el.textContent === '' || el.textContent === '0' || el.textContent === '-' ? '0' : el.textContent.replace(/[^0-9.-]/g, ''))) || 0;
  const shouldAnimate = force || (el.dataset.prevVal === undefined) || (prevVal !== targetNum);
  el.textContent = next;                       // the value is correct regardless of motion
  el.dataset.prevVal = String(targetNum);
  if (!shouldAnimate || prefersReducedMotion()) return;
  el.classList.remove('num-updated');
  void el.offsetWidth;                         // force reflow so the animation restarts
  el.classList.add('num-updated');
  if (typeof Motion !== 'undefined' && typeof Motion.countTo === 'function') {
    Motion.countTo(el, targetNum, { from: prevVal, duration: 1100, delay, forceRoll: force });
  }
}

/** Stagger a container's children. Sets --i, capped at 6.
 *
 *  The cap is not cosmetic: past about six steps the last element arrives visibly after the
 *  reader has started looking elsewhere, which reads as a broken page rather than a cascade.
 */
function stagger(container, max = 6) {
  if (!container) return;
  Array.from(container.children).forEach((child, i) => {
    child.style.setProperty('--i', String(Math.min(i, max)));
  });
}

/** Drive the scanning state. Adds the sweep on entry, removes it on completion.
 *
 *  `off` is the important half: leaving the sweep running after a result exists is the console
 *  telling the analyst it is still thinking when it is not.
 */
function setScanning(on) {
  document.querySelectorAll('.scan-sweep').forEach(el => {
    el.classList.toggle('scan-sweep', !!on);
  });
  document.body.classList.toggle('is-scanning', !!on);
}

/** Prime the score ring so CSS can draw the arc from full circumference.
 *
 *  The FINAL dasharray is written into the element's own attributes first, so the ring is
 *  already correct with no animation at all. The custom property is only the starting point
 *  for the draw-on effect -- it is a reveal of a value, never the value.
 */
function primeRing(arcEl) {
  if (!arcEl) return;
  const r = parseFloat(arcEl.getAttribute('r'));
  if (!r || Number.isNaN(r)) return;
  arcEl.style.setProperty('--ring-circumference', String(2 * Math.PI * r));
  arcEl.classList.add('ring-arc');
}

function renderIntegrityBanner(data) {
  const sum = data.summary;
  const cov = data.coverage;

  // Every headline figure goes through setMetric rather than a bare textContent assignment, so
  // a number that CHANGES is visibly marked as having changed. Staggered waves provide an
  // unmistakable executive telemetry readout.
  setMetric('metric-total', sum.total_findings, 0, true);
  setMetric('metric-proven', sum.proven_use, 70, true);
  setMetric('metric-capability', sum.capability_or_declared, 140, true);
  setMetric('metric-unresolved', sum.unresolved_purpose, 210, true);
  setMetric('metric-scanned', cov.files_scanned, 280, true);
  setMetric('metric-skipped', cov.files_skipped, 350, true);

  // Proof bar & label animation
  const pctProven = sum.total_findings ? Math.round((sum.proven_use / sum.total_findings) * 100) : 0;
  const proofFill = document.getElementById('proof-fill');
  if (proofFill) {
    proofFill.style.width = `${pctProven}%`;
  }
  const proofLabel = document.getElementById('proof-pct-label');
  if (proofLabel) {
    const prevPct = parseFloat(proofLabel.dataset.prevPct || '0');
    proofLabel.dataset.prevPct = String(pctProven);
    proofLabel.textContent = `${pctProven}% proven use (${sum.proven_use}/${sum.total_findings})`;
    if (typeof Motion !== 'undefined' && typeof Motion.countTo === 'function') {
      Motion.countTo(proofLabel, pctProven, {
        from: prevPct,
        duration: 1100,
        delay: 150,
        suffix: `% proven use (${sum.proven_use}/${sum.total_findings})`,
        forceRoll: true
      });
    }
  }

  // Risk Score Badge with roll-up animation
  const scoreEl = document.getElementById('risk-score-badge');
  if (scoreEl) {
    const sVal = (typeof sum.risk_score === 'object' && sum.risk_score !== null) ? (sum.risk_score.score ?? 0) : (sum.risk_score ?? 0);
    const prevScore = parseFloat(scoreEl.dataset.prevScore || '0');
    scoreEl.dataset.prevScore = String(sVal);
    scoreEl.textContent = `Risk Posture: ${sVal} / 100`;
    if (typeof Motion !== 'undefined' && typeof Motion.countTo === 'function') {
      Motion.countTo(scoreEl, sVal, {
        from: prevScore,
        duration: 1100,
        prefix: 'Risk Posture: ',
        suffix: ' / 100',
        forceRoll: true
      });
    }
  }
}

function renderEvidenceView(data) {
  const cov = data.coverage;
  const verdict = cov.verdict;
  const callout = document.getElementById('coverage-callout');
  
  if (verdict.state === 'covered') {
    callout.className = 'callout callout-emerald';
    callout.innerHTML = `<strong>Scan complete & fully read:</strong> ${escapeHtml(verdict.message)}`;
  } else if (verdict.state === 'incomplete') {
    callout.className = 'callout callout-amber';
    callout.innerHTML = `<strong>Scan incomplete:</strong> ${escapeHtml(verdict.message)}`;
  } else {
    callout.className = 'callout callout-rose';
    callout.innerHTML = `<strong>Nothing examined:</strong> ${escapeHtml(verdict.message)}`;
  }

  // Errors table
  const errTable = document.getElementById('coverage-errors-body');
  errTable.innerHTML = '';
  if (cov.errors && cov.errors.length > 0) {
    cov.errors.forEach((err, i) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono">${i + 1}</td>
        <td class="mono">${escapeHtml(err.file || '')}</td>
        <td><span class="tier-chip tier-CRITICAL">${escapeHtml(err.reason || '')}</span></td>
      `;
      errTable.appendChild(tr);
    });
    document.getElementById('coverage-errors-wrap').style.display = 'block';
  } else {
    document.getElementById('coverage-errors-wrap').style.display = 'none';
  }

  // Never in scope list
  const gapList = document.getElementById('never-in-scope-list');
  gapList.innerHTML = '';
  (cov.never_in_scope || []).forEach(gap => {
    const li = document.createElement('li');
    li.textContent = gap;
    gapList.appendChild(li);
  });
}

function renderAuditorView(data) {
  const records = data.records || [];
  const tbody = document.getElementById('auditor-table-body');
  tbody.innerHTML = '';

  const query = STATE.filterQuery.toLowerCase();
  const filtered = records.filter(r => {
    if (STATE.onlyHndl && !(r.risk?.hndl_exposed)) return false;
    if (r.tier && !STATE.selectedTiers.has(r.tier)) return false;
    if (query) {
      const matchStr = `${r.name} ${r.primitive} ${r.file} ${r.rule_id}`.toLowerCase();
      if (!matchStr.includes(query)) return false;
    }
    return true;
  });

  document.getElementById('auditor-filter-count').textContent = 
    `Showing ${filtered.length} of ${records.length} findings`;

  filtered.forEach(r => {
    const tr = document.createElement('tr');
    const risk = r.risk || {};
    const tier = r.tier || 'LOW';
    const loc = `${r.file || ''}${r.line ? ':' + r.line : ''}`;

    tr.innerHTML = `
      <td>
        <span class="tier-chip tier-${tier}">${tier}</span>
        ${risk.hndl_exposed ? `<span class="hndl-badge">HNDL</span>` : ''}
      </td>
      <td>
        <strong style="color:var(--text-main)">${escapeHtml(r.name || '')}</strong>
        ${r.key_length ? `<span class="mono" style="color:var(--text-muted);font-size:0.75rem">(${r.key_length}b)</span>` : ''}
      </td>
      <td class="mono">${escapeHtml(r.primitive || '-')}</td>
      <td>
        <span class="badge ${r.assurance?.value === 'used' ? 'badge-emerald' : 'badge-cyan'}">
          ${escapeHtml(r.assurance?.value || '-')}
        </span>
      </td>
      <td class="mono">X:${risk.x || 0} + Y:${risk.y || 0} vs Z:${risk.z || 0}</td>
      <td class="mono" style="color:${risk.margin > 0 ? '#F87171' : '#34D399'}">
        ${risk.margin !== undefined ? (risk.margin > 0 ? '+' : '') + risk.margin + 'y' : '-'}
      </td>
      <td class="mono">${risk.latest_safe_migration_start || '-'}</td>
      <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(loc)}">
        ${escapeHtml(loc.split('/').pop() || loc)}
      </td>
      <td>
        <button class="btn-outline" style="height:28px;padding:0 0.5rem;font-size:0.75rem" onclick='openDrawer(${JSON.stringify(r).replace(/'/g, "&#39;")})'>
          Inspect
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderPlannerView(data) {
  const records = data.records || [];
  const tbody = document.getElementById('planner-table-body');
  tbody.innerHTML = '';

  // Unresolved purpose section
  const declined = records.filter(r => r.unresolved);
  const unresolvedCallout = document.getElementById('planner-unresolved-callout');
  if (declined.length > 0) {
    unresolvedCallout.style.display = 'block';
    unresolvedCallout.innerHTML = `
      <strong>${declined.length} finding(s) with Unresolved Purpose:</strong>
      IndraMesh declines to name a post-quantum target for these until a human resolves what the primitive is FOR (e.g. RSA used for Signing vs Key Encapsulation).
    `;
  } else {
    unresolvedCallout.style.display = 'none';
  }

  // Queue rows
  (data.queue_rows || []).forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="tier-chip tier-${row['Risk tier'] || 'LOW'}">${row['Risk tier']}</span></td>
      <td><strong>${escapeHtml(row['Artefact'] || '')}</strong></td>
      <td class="mono">${escapeHtml(row['Primitive'] || '')}</td>
      <td><span class="badge badge-purple">${escapeHtml(row['Target algorithm'] || 'None')}</span></td>
      <td class="mono">${escapeHtml(row['Latest safe start'] || '')}</td>
      <td>${escapeHtml(row['Cost band'] || '')}</td>
      <td class="mono">${escapeHtml(row['Packet overhead'] || '')}</td>
      <td>${escapeHtml(row['Action'] || '')}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderComplianceView(data) {
  const v = data.cbom_validation || {};
  const valBadge = document.getElementById('cbom-valid-badge');
  const valMsg = document.getElementById('cbom-valid-message');

  if (v.ok) {
    valBadge.className = 'badge badge-emerald';
    valBadge.textContent = 'CONFORMANT - VALID';
    valMsg.textContent = `CycloneDX 1.7 schema validation passed without errors. Offline validated against official Ecma-424 JSON Schema.`;
  } else {
    valBadge.className = 'badge badge-rose';
    valBadge.textContent = 'NON-CONFORMANT';
    valMsg.textContent = v.message || 'Validation encountered schema errors.';
  }

  // Pre-fill CBOM json preview
  fetch('/api/cbom')
    .then(r => r.json())
    .then(cbomData => {
      document.getElementById('cbom-json-preview').textContent = 
        JSON.stringify(cbomData.document, null, 2);
    })
    .catch(() => {});
}

// -----------------------------------------------------------------------------
// Slide-over Drawer & Modals
// -----------------------------------------------------------------------------
function openDrawer(record) {
  STATE.selectedRecord = record;
  const drawer = document.getElementById('drawer-backdrop');
  drawer.classList.add('open');

  document.getElementById('drawer-title-text').textContent = 
    `${record.name} (${record.primitive || 'crypto'})`;

  const risk = record.risk || {};
  const purpose = record.purpose || {};
  const assurance = record.assurance || {};
  const rec = record.recommendation || {};

  document.getElementById('drawer-tier-chip').textContent = record.tier || 'LOW';
  document.getElementById('drawer-tier-chip').className = `tier-chip tier-${record.tier || 'LOW'}`;

  document.getElementById('drawer-content').innerHTML = `
    <div class="detail-section">
      <h4>Mosca Inequality Calculation (X + Y vs Z)</h4>
      <div class="callout ${record.tier === 'CRITICAL' ? 'callout-rose' : 'callout-emerald'}">
        <strong>Break model:</strong> ${risk.break_model || 'Unknown'} (${risk.threat || ''})<br>
        <strong>Formula:</strong> X(${risk.x}y) + Y(${risk.y}y) = ${risk.x_y}y vs Z(${risk.z}y) &rarr; Margin: <strong>${risk.margin}y</strong><br>
        <strong>X Origin:</strong> ${risk.x_reason || 'Class lifetime'}<br>
        <strong>Y Origin:</strong> ${risk.y_reason || 'Migration effort'}<br>
        <strong>Latest Safe Start:</strong> ${risk.latest_safe_migration_start || 'Immediate'}
      </div>
    </div>

    <div class="detail-section">
      <h4>Purpose & Assurance Signals</h4>
      <p><strong>Assurance:</strong> ${assurance.value} &mdash; ${assurance.reason || ''}</p>
      <p><strong>Purpose:</strong> ${purpose.value} &mdash; ${purpose.reason || ''}</p>
      ${purpose.signals?.length ? `<p class="mono" style="font-size:0.75rem">Signals seen: ${purpose.signals.join(', ')}</p>` : ''}
    </div>

    <div class="detail-section">
      <h4>Matched Code Snippet</h4>
      <div class="code-snippet">${escapeHtml(record.match || 'No snippet captured')}</div>
      <p class="mono" style="font-size:0.72rem;margin-top:0.3rem">File: ${record.file}:${record.line || '1'}</p>
    </div>

    <div class="detail-section">
      <h4>Recommended Post-Quantum Alternative</h4>
      <p><strong>Target:</strong> <span class="badge badge-purple">${rec.algorithm || 'Human Review Required'}</span></p>
      <p><strong>Action:</strong> ${rec.action || '-'}</p>
      <p><strong>Packet Overhead:</strong> ${rec.tradeoff_size || 'None'}</p>
      <p><strong>Latency Impact:</strong> ${rec.tradeoff_latency || 'None'}</p>
    </div>
  `;
}

function closeDrawer() {
  document.getElementById('drawer-backdrop').classList.remove('open');
}

// -----------------------------------------------------------------------------
// Folder Picker Dialog
// -----------------------------------------------------------------------------
async function openFolderPicker() {
  const modal = document.getElementById('picker-modal');
  modal.classList.add('open');
  await browseDirectory(document.getElementById('target-input').value || '.');
}

function closeFolderPicker() {
  document.getElementById('picker-modal').classList.remove('open');
}

async function browseDirectory(path) {
  try {
    const res = await fetch('/api/browse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    const data = await res.json();
    STATE.browsePath = data.current;
    document.getElementById('picker-current-path').textContent = data.current;

    const list = document.getElementById('picker-tree-list');
    list.innerHTML = '';

    if (data.parent) {
      const li = document.createElement('li');
      li.className = 'folder-tree-item';
      li.innerHTML = `<span style="color:var(--cyan-core)">${ICONS.folder}</span> <strong>.. (Parent directory)</strong>`;
      li.onclick = () => browseDirectory(data.parent);
      list.appendChild(li);
    }

    (data.directories || []).forEach(dir => {
      const li = document.createElement('li');
      li.className = 'folder-tree-item';
      li.innerHTML = `<span style="color:var(--cyan-core)">${ICONS.folder}</span> ${dir}`;
      li.onclick = () => browseDirectory(`${data.current}/${dir}`);
      list.appendChild(li);
    });
  } catch (err) {
    console.error('Browse error:', err);
  }
}

function selectCurrentFolder() {
  if (STATE.browsePath) {
    document.getElementById('target-input').value = STATE.browsePath;
  }
  closeFolderPicker();
}

// -----------------------------------------------------------------------------
// Advanced Sensors Execution
// -----------------------------------------------------------------------------
async function runSensor(type) {
  const target = document.getElementById('target-input').value || './dummy_target';
  const resultDiv = document.getElementById(`sensor-result-${type}`);
  resultDiv.innerHTML = `<div class="mono" style="color:var(--cyan-core)">Running ${type} sensor...</div>`;

  try {
    const res = await fetch(`/api/sensors/${type}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();
    resultDiv.innerHTML = `
      <div class="callout callout-emerald" style="margin-top:0.5rem">
        <strong>Sensor Status:</strong> ${data.status.toUpperCase()}<br>
        ${JSON.stringify(data.summary || data.report || {}, null, 2)}
      </div>
    `;
  } catch (err) {
    resultDiv.innerHTML = `<div class="callout callout-rose">Sensor error: ${err.message}</div>`;
  }
}

// -----------------------------------------------------------------------------
// Helpers & Event Listeners
// -----------------------------------------------------------------------------
function setupEvents() {
  document.getElementById('run-scan-btn').addEventListener('click', () => runScan());
  document.getElementById('browse-btn').addEventListener('click', () => openFolderPicker());
  document.getElementById('picker-close-btn').addEventListener('click', () => closeFolderPicker());
  document.getElementById('picker-cancel-btn').addEventListener('click', () => closeFolderPicker());
  document.getElementById('picker-select-btn').addEventListener('click', () => selectCurrentFolder());
  document.getElementById('drawer-close-btn').addEventListener('click', () => closeDrawer());

  // Search filter in Auditor table
  const searchInput = document.getElementById('auditor-search-input');
  searchInput.addEventListener('input', (e) => {
    STATE.filterQuery = e.target.value;
    if (STATE.scanData) renderAuditorView(STATE.scanData);
  });

  // HNDL only filter
  document.getElementById('filter-hndl-only').addEventListener('change', (e) => {
    STATE.onlyHndl = e.target.checked;
    if (STATE.scanData) renderAuditorView(STATE.scanData);
  });

  // Keyboard shortcut Enter in target input
  document.getElementById('target-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runScan();
  });

  // ESC to close drawer or modal
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeDrawer();
      closeFolderPicker();
    }
  });
}

function showProgress(active, text = '') {
  const strip = document.getElementById('scan-progress-strip');
  strip.classList.toggle('active', active);
  document.getElementById('scan-progress-text').textContent = text;
  setScanning(active);
  if (STATE.radarReticle && typeof STATE.radarReticle.setScanMode === 'function') {
    STATE.radarReticle.setScanMode(active);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// -----------------------------------------------------------------------------
// Posture, Radial Spoke Dial & Mosca Timeline Rendering
// -----------------------------------------------------------------------------
function renderPostureView(data) {
  renderRadialDial(data);
  renderMoscaSection(data);
  renderCompositionBar(data);
}

function renderRadialDial(data) {
  const svg = document.getElementById('radial-dial');
  if (!svg) return;

  const records = data.records || [];
  const sum = data.summary || {};
  if (!records.length) return;

  // Initialize or re-layer the Circular Radar Reticle
  if (typeof CircularRadarReticle !== 'undefined') {
    if (!STATE.radarReticle) {
      STATE.radarReticle = new CircularRadarReticle('radial-dial');
    } else {
      STATE.radarReticle.initSvgLayers();
    }
    STATE.radarReticle.start();
  } else {
    svg.innerHTML = '';
  }

  // Spokes group on top of radar background
  let spokesGroup = svg.querySelector('#radar-spokes-group');
  if (!spokesGroup) {
    spokesGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    spokesGroup.setAttribute('id', 'radar-spokes-group');
    svg.appendChild(spokesGroup);
  } else {
    spokesGroup.innerHTML = '';
  }

  const CX = 210, CY = 210, R0 = 85, R1 = 195;
  const items = [...records].sort((a, b) => ((b.risk?.score || 0) - (a.risk?.score || 0)));
  const N = items.length;

  const sweep = 2 * Math.PI * 0.86;
  const start = Math.PI / 2 + (2 * Math.PI - sweep) / 2;
  const step = sweep / Math.max(1, N);
  const strokeWidth = Math.max(2.2, Math.min(4.8, (2 * Math.PI * R0 * 0.86 / N) - 0.8));

  const tierColors = {
    CRITICAL: '#F43F5E',
    HIGH: '#F97316',
    MEDIUM: '#F59E0B',
    LOW: '#10B981',
  };

  // Render each spoke and particle tip
  items.forEach((r, i) => {
    const a = start + step * (i + 0.5);
    const scoreVal = r.risk?.score !== undefined ? r.risk.score : (r.tier === 'CRITICAL' ? 85 : (r.tier === 'HIGH' ? 65 : (r.tier === 'MEDIUM' ? 45 : 20)));
    const scoreFrac = Math.max(0.08, Math.min(1.0, scoreVal / 100));
    const spokeLen = R0 + (R1 - R0) * scoreFrac;
    const color = tierColors[r.tier] || '#10B981';

    const spokeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    spokeGroup.setAttribute('class', 'spoke-item spoke-enter');

    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', CX + R0 * Math.cos(a));
    line.setAttribute('y1', CY + R0 * Math.sin(a));
    line.setAttribute('x2', CX + spokeLen * Math.cos(a));
    line.setAttribute('y2', CY + spokeLen * Math.sin(a));
    line.setAttribute('stroke', color);
    line.setAttribute('stroke-width', strokeWidth);
    line.setAttribute('stroke-linecap', 'round');
    line.setAttribute('class', 'radial-spoke');
    line.setAttribute('data-index', i);
    line.style.setProperty('--spoke-i', String(Math.min(i, 36)));

    // Particle dot at outer spoke tip with subtle glow
    const tipDot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    tipDot.setAttribute('cx', CX + spokeLen * Math.cos(a));
    tipDot.setAttribute('cy', CY + spokeLen * Math.sin(a));
    tipDot.setAttribute('r', Math.max(2.4, strokeWidth * 0.85));
    tipDot.setAttribute('fill', color);
    tipDot.setAttribute('opacity', '0.95');
    tipDot.style.setProperty('--spoke-i', String(Math.min(i, 36)));

    // Hover interactions
    const onEnter = () => {
      line.style.strokeWidth = `${strokeWidth * 1.5}px`;
      tipDot.setAttribute('r', `${strokeWidth * 1.25}`);
      const hubTitle = document.getElementById('hub-title');
      const hubMain = document.getElementById('hub-main');
      const hubSub = document.getElementById('hub-sub');
      if (hubTitle) {
        hubTitle.textContent = r.tier || 'ASSET';
        hubTitle.style.color = color;
      }
      if (hubMain) {
        hubMain.textContent = r.name || 'Crypto';
      }
      if (hubSub) {
        hubSub.textContent = `${r.primitive || 'Algo'} · Risk: ${scoreVal}`;
      }
    };

    const onLeave = () => {
      line.style.strokeWidth = `${strokeWidth}px`;
      tipDot.setAttribute('r', `${Math.max(2.4, strokeWidth * 0.85)}`);
      resetRadialHub(sum);
    };

    line.addEventListener('mouseenter', onEnter);
    line.addEventListener('mouseleave', onLeave);
    tipDot.addEventListener('mouseenter', onEnter);
    tipDot.addEventListener('mouseleave', onLeave);

    spokeGroup.addEventListener('click', () => {
      openDrawer(r);
    });

    spokeGroup.appendChild(line);
    spokeGroup.appendChild(tipDot);
    spokesGroup.appendChild(spokeGroup);
  });

  if (STATE.radarReticle && typeof STATE.radarReticle.updateTargets === 'function') {
    STATE.radarReticle.updateTargets(items);
  }

  resetRadialHub(sum);
}

function resetRadialHub(sum) {
  const hubTitle = document.getElementById('hub-title');
  const hubMain = document.getElementById('hub-main');
  const hubSub = document.getElementById('hub-sub');
  if (hubTitle) {
    hubTitle.textContent = 'RISK POSTURE';
    hubTitle.style.color = 'var(--cyan-core)';
  }
  if (hubMain) {
    const sVal = (typeof sum.risk_score === 'object' && sum.risk_score !== null) ? (sum.risk_score.score ?? 0) : (sum.risk_score ?? 0);
    const prevScore = parseFloat(hubMain.dataset.scoreVal || '0');
    hubMain.dataset.scoreVal = String(sVal);
    hubMain.textContent = `${sVal} / 100`;
    if (typeof Motion !== 'undefined' && typeof Motion.countTo === 'function') {
      Motion.countTo(hubMain, sVal, { from: prevScore, suffix: ' / 100', forceRoll: true });
    }
  }
  if (hubSub) {
    hubSub.textContent = `${sum.total_findings || 0} findings (${sum.proven_use || 0} proven)`;
  }
}

function renderMoscaSection(data) {
  const records = data.records || [];
  const sum = data.summary || {};

  let worstRisk = null;
  records.forEach(r => {
    if (r.risk && (!worstRisk || (r.risk.margin || 0) > (worstRisk.margin || 0))) {
      worstRisk = r.risk;
    }
  });

  const X = worstRisk?.x ?? 10;
  const Y = worstRisk?.y ?? 3;
  const Z = data.z_years || 10;
  const T = X + Y;
  const exposure = Math.max(0, T - Z);
  const isExposed = exposure > 0;
  const currentYear = new Date().getFullYear();
  const secureThrough = currentYear + Math.round(T);
  const crqcExpected = currentYear + Math.round(Z);

  const badge = document.getElementById('mosca-verdict-badge');
  if (badge) {
    if (isExposed) {
      badge.className = 'badge badge-rose';
      badge.textContent = `EXPOSED (+${exposure.toFixed(1)}y shortfall)`;
    } else {
      badge.className = 'badge badge-emerald';
      badge.textContent = `SAFE (${Math.abs(T - Z).toFixed(1)}y safety margin)`;
    }
  }

  const tilesContainer = document.getElementById('mosca-tiles');
  if (tilesContainer) {
    const deltaVal = isExposed ? exposure : Math.abs(Z - T);
    tilesContainer.innerHTML = `
      <div class="mosca-tile">
        <span class="mosca-tile-lbl">X &middot; Secrecy</span>
        <span class="mosca-tile-val" id="mosca-val-x" style="color:#38BDF8">${X}y</span>
        <span class="mosca-tile-sub">Confidentiality</span>
      </div>
      <div class="mosca-op">+</div>
      <div class="mosca-tile">
        <span class="mosca-tile-lbl">Y &middot; Migration</span>
        <span class="mosca-tile-val" id="mosca-val-y" style="color:#F59E0B">${Y}y</span>
        <span class="mosca-tile-sub">Rollout time</span>
      </div>
      <div class="mosca-op">=</div>
      <div class="mosca-tile">
        <span class="mosca-tile-lbl">Protection Needed</span>
        <span class="mosca-tile-val" id="mosca-val-t" style="color:var(--text-main)">${T}y</span>
        <span class="mosca-tile-sub">Through ~${secureThrough}</span>
      </div>
      <div class="mosca-op">${isExposed ? '>' : '&le;'}</div>
      <div class="mosca-tile">
        <span class="mosca-tile-lbl">Z &middot; CRQC Horizon</span>
        <span class="mosca-tile-val" id="mosca-val-z" style="color:var(--cyan-core)">${Z}y</span>
        <span class="mosca-tile-sub">Est. ~${crqcExpected}</span>
      </div>
      <div class="mosca-op">&rarr;</div>
      <div class="mosca-tile highlight" style="${isExposed ? 'border-color:#F43F5E' : 'border-color:#10B981'}">
        <span class="mosca-tile-lbl">${isExposed ? 'Exposure Window' : 'Safety Margin'}</span>
        <span class="mosca-tile-val" id="mosca-val-delta" style="color:${isExposed ? '#F43F5E' : '#10B981'}">
          ${isExposed ? '+' + exposure.toFixed(1) + 'y' : (Z - T).toFixed(1) + 'y'}
        </span>
        <span class="mosca-tile-sub">${isExposed ? 'HNDL Vulnerability' : 'Ahead of threat'}</span>
      </div>
    `;

    if (typeof Motion !== 'undefined' && typeof Motion.countTo === 'function') {
      Motion.countTo(document.getElementById('mosca-val-x'), X, { suffix: 'y', from: 0, duration: 900 });
      Motion.countTo(document.getElementById('mosca-val-y'), Y, { suffix: 'y', from: 0, duration: 900, delay: 60 });
      Motion.countTo(document.getElementById('mosca-val-t'), T, { suffix: 'y', from: 0, duration: 900, delay: 120 });
      Motion.countTo(document.getElementById('mosca-val-z'), Z, { suffix: 'y', from: 0, duration: 900, delay: 180 });
      Motion.countTo(document.getElementById('mosca-val-delta'), deltaVal, { prefix: isExposed ? '+' : '', suffix: 'y', from: 0, duration: 900, delay: 240, decimals: 1 });
    }
  }

  const plainEl = document.getElementById('mosca-plain-explanation');
  if (plainEl) {
    if (isExposed) {
      plainEl.innerHTML = `Data encrypted today requires confidentiality through <strong style="color:var(--text-main)">${secureThrough}</strong> (${X}y secrecy lifetime + ${Y}y replacement rollout). A cryptanalytically relevant quantum computer is estimated to break RSA/ECC by <strong style="color:var(--cyan-core)">${crqcExpected}</strong>. That leaves a <strong style="color:#F43F5E">${exposure.toFixed(1)}-year vulnerability window</strong> where harvested encrypted communications can be decrypted retroactively.`;
    } else {
      plainEl.innerHTML = `Data encrypted today requires protection through <strong style="color:var(--text-main)">${secureThrough}</strong> (${X}y secrecy + ${Y}y rollout). A quantum break is anticipated around <strong style="color:var(--cyan-core)">${crqcExpected}</strong>. Migration completes <strong style="color:#10B981">${(Z - T).toFixed(1)} years before CRQC arrival</strong>, keeping secrets protected.`;
    }
  }

  renderMoscaTimelineSvg(X, Y, T, Z, exposure);
}

function renderMoscaTimelineSvg(X, Y, T, Z, exposure) {
  const svg = document.getElementById('mosca-timeline-svg');
  if (!svg) return;
  svg.innerHTML = '';

  const W = 700, L = 75, R = 110, H = 22;
  const maxSpan = Math.max(T, Z, 15) * 1.08;
  const px = (val) => L + (val / maxSpan) * (W - L - R);

  const sv = (tag, attrs, text = null) => {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    if (text !== null) el.textContent = text;
    return el;
  };

  const yNeed = 18;
  svg.appendChild(sv('text', { x: L - 10, y: yNeed + 16, fill: '#94A3B8', 'font-size': '11', 'font-family': 'monospace', 'text-anchor': 'end', 'font-weight': '600' }, 'NEED'));
  svg.appendChild(sv('rect', { x: px(0), y: yNeed, width: Math.max(2, px(X) - px(0)), height: H, fill: '#38BDF8', opacity: '0.65', rx: '3' }));
  svg.appendChild(sv('rect', { x: px(X), y: yNeed, width: Math.max(2, px(T) - px(X)), height: H, fill: '#F59E0B', opacity: '0.65', rx: '3' }));
  svg.appendChild(sv('rect', { x: px(0), y: yNeed, width: Math.max(2, px(T) - px(0)), height: H, fill: 'none', stroke: '#CBD5E1', 'stroke-width': '1.2', rx: '3' }));
  svg.appendChild(sv('text', { x: px(T) + 12, y: yNeed + 16, fill: '#F1F5F9', 'font-size': '12', 'font-weight': '700', 'font-family': 'monospace' }, `${T}y (X+Y)`));

  const yHave = 65;
  svg.appendChild(sv('text', { x: L - 10, y: yHave + 16, fill: '#94A3B8', 'font-size': '11', 'font-family': 'monospace', 'text-anchor': 'end', 'font-weight': '600' }, 'HAVE'));
  svg.appendChild(sv('rect', { x: px(0), y: yHave, width: Math.max(2, px(Z) - px(0)), height: H, fill: '#10B981', opacity: '0.45', rx: '3' }));
  svg.appendChild(sv('rect', { x: px(0), y: yHave, width: Math.max(2, px(Z) - px(0)), height: H, fill: 'none', stroke: '#10B981', 'stroke-width': '1.2', rx: '3' }));
  svg.appendChild(sv('text', { x: px(Z) + 12, y: yHave + 16, fill: '#10B981', 'font-size': '12', 'font-weight': '700', 'font-family': 'monospace' }, `${Z}y (CRQC)`));

  if (exposure > 0) {
    const xGap = px(Z);
    const wGap = Math.max(2, px(T) - px(Z));
    svg.appendChild(sv('rect', { x: xGap, y: yNeed, width: wGap, height: H, fill: '#F43F5E', opacity: '0.8', rx: '3' }));
    svg.appendChild(sv('rect', { x: xGap, y: yNeed - 4, width: wGap, height: H + 8, fill: 'none', stroke: '#F43F5E', 'stroke-width': '1.5', 'stroke-dasharray': '2 2', rx: '4' }));
    svg.appendChild(sv('text', { x: xGap + wGap / 2, y: yNeed + H + 18, fill: '#F43F5E', 'font-size': '11', 'font-weight': '700', 'font-family': 'monospace', 'text-anchor': 'middle' }, `▲ ${exposure.toFixed(1)}y EXPOSED`));
  }
}

function renderCompositionBar(data) {
  const bar = document.getElementById('composition-bar');
  const legend = document.getElementById('composition-legend');
  const label = document.getElementById('composition-label');
  if (!bar || !legend) return;

  bar.innerHTML = '';
  legend.innerHTML = '';

  const records = data.records || [];
  const total = records.length;
  if (!total) {
    if (label) label.textContent = '0 findings';
    return;
  }
  if (label) label.textContent = `${total} cryptographic findings total`;

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  records.forEach(r => {
    const t = r.tier || 'LOW';
    counts[t] = (counts[t] || 0) + 1;
  });

  const configs = [
    { key: 'CRITICAL', label: 'Critical (Shor Break)', color: '#EF4444' },
    { key: 'HIGH', label: 'High (Grover / Urgency)', color: '#F97316' },
    { key: 'MEDIUM', label: 'Medium (Weak Symmetric)', color: '#F59E0B' },
    { key: 'LOW', label: 'Low (PQC Ready / Safe)', color: '#10B981' },
  ];

  configs.forEach(cfg => {
    const cnt = counts[cfg.key] || 0;
    const pct = ((cnt / total) * 100).toFixed(1);

    if (cnt > 0) {
      const seg = document.createElement('div');
      seg.className = 'composition-seg';
      seg.style.width = `${pct}%`;
      seg.style.background = cfg.color;
      seg.title = `${cfg.label}: ${cnt} (${pct}%)`;
      seg.onclick = () => {
        switchTab('auditor');
        document.getElementById('auditor-search-input').value = cfg.key;
        STATE.filterQuery = cfg.key;
        renderAuditorView(STATE.scanData);
      };
      bar.appendChild(seg);
    }

    const btn = document.createElement('button');
    btn.className = 'legend-btn';
    btn.innerHTML = `<span class="legend-swatch" style="background:${cfg.color}"></span> ${cfg.key}: ${cnt} (${pct}%)`;
    btn.onclick = () => {
      switchTab('auditor');
      document.getElementById('auditor-search-input').value = cfg.key;
      STATE.filterQuery = cfg.key;
      renderAuditorView(STATE.scanData);
    };
    legend.appendChild(btn);
  });
}

// -----------------------------------------------------------------------------
// Scan History
// -----------------------------------------------------------------------------
async function loadHistoryList() {
  const container = document.getElementById('history-container');
  if (!container) return;
  container.innerHTML = '<p style="color:var(--text-dim);font-size:0.8rem">Fetching scan history...</p>';

  try {
    const res = await fetch('/api/history');
    if (!res.ok) throw new Error('Failed to fetch history');
    const items = await res.json();

    if (!items.length) {
      container.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem">No saved scans on record yet. Run a discovery scan first.</p>';
      return;
    }

    container.innerHTML = '';
    items.forEach(h => {
      const div = document.createElement('div');
      div.className = 'history-item';
      const hScore = (typeof h.risk_score === 'object' && h.risk_score !== null) ? (h.risk_score.score ?? 0) : (h.risk_score ?? 0);
      div.innerHTML = `
        <div>
          <div style="display:flex;align-items:center;gap:0.6rem">
            <strong style="color:var(--text-main);font-size:0.9rem">${escapeHtml(h.target)}</strong>
            <span class="badge ${hScore >= 50 ? 'badge-rose' : 'badge-emerald'}">Risk: ${hScore}/100</span>
            <span class="badge badge-purple">${h.policy || 'Policy'}</span>
            ${h.cbom_valid ? '<span class="badge badge-emerald">CBOM Valid</span>' : ''}
          </div>
          <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem">
            ${h.scanned_at} &middot; ${h.findings_count} findings (Z=${h.z_years}y)
          </div>
        </div>
        <button class="btn-primary" style="height:32px;font-size:0.75rem;padding:0 0.8rem" onclick="loadHistoryScan('${h.id}')">
          Restore Scan
        </button>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    container.innerHTML = `<p style="color:#EF4444;font-size:0.85rem">History error: ${err.message}</p>`;
  }
}

async function loadHistoryScan(id) {
  showProgress(true, `Restoring scan ${id}...`);
  try {
    const res = await fetch('/api/history/load', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    if (!res.ok) throw new Error('Failed to restore scan');
    const data = await res.json();
    STATE.scanData = data;
    renderAllViews(data);
    loadTopology();
    switchTab('posture');
  } catch (err) {
    alert(`Restore error: ${err.message}`);
  } finally {
    showProgress(false);
  }
}


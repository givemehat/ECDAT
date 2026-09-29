const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');

const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const TARGET_URL = 'http://127.0.0.1:8501';

const ASSETS_DIR = path.resolve(__dirname, '..', 'assets');
const DOCS_ASSETS_DIR = path.resolve(__dirname, '..', 'docs', 'assets');
const ROOT_ASSETS_DIR = path.resolve(__dirname, '..', '..', 'assets');
const ROOT_DOCS_ASSETS_DIR = path.resolve(__dirname, '..', '..', 'docs', 'assets');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

async function copyToAllAssetDirs(filename) {
  const src = path.join(ASSETS_DIR, filename);
  if (!fs.existsSync(src)) return;

  const targets = [DOCS_ASSETS_DIR, ROOT_ASSETS_DIR, ROOT_DOCS_ASSETS_DIR];
  for (const t of targets) {
    ensureDir(t);
    fs.copyFileSync(src, path.join(t, filename));
  }
}

(async () => {
  ensureDir(ASSETS_DIR);
  console.log('[*] Launching headless browser via Edge...');

  const browser = await puppeteer.launch({
    executablePath: EDGE_PATH,
    headless: 'new',
    defaultViewport: {
      width: 1520,
      height: 980,
      deviceScaleFactor: 2, // High-DPI / Retina quality
    },
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu']
  });

  const page = await browser.newPage();
  console.log(`[*] Navigating to ${TARGET_URL}...`);
  await page.goto(TARGET_URL, { waitUntil: 'networkidle0', timeout: 30000 });

  // Wait for initial render
  await page.waitForSelector('#run-scan-btn');

  // Trigger discovery scan on ./dummy_target to populate all tabs with live findings
  console.log('[*] Triggering discovery scan on ./dummy_target...');
  await page.click('#run-scan-btn');
  
  // Wait for scan findings to populate
  await page.waitForFunction(() => {
    const totalEl = document.getElementById('metric-total');
    return totalEl && totalEl.textContent && parseInt(totalEl.textContent, 10) > 0;
  }, { timeout: 15000 });

  // Wait 1.5s for charts and animations to settle
  await new Promise(r => setTimeout(r, 1500));
  console.log('[+] Scan complete and estate data loaded!');

  // 1. Overall Dashboard Overview (Top half + posture dial)
  console.log('[*] Capturing 1: prototype-dashboard-posture.png');
  const dashPath = path.join(ASSETS_DIR, 'prototype-dashboard-posture.png');
  await page.screenshot({ path: dashPath });
  await copyToAllAssetDirs('prototype-dashboard-posture.png');

  // 2. Posture & Dial Card (Hero radial dial & Mosca timeline)
  console.log('[*] Capturing 2: prototype-radar-posture-dial.png');
  const postureCard = await page.$('#tab-posture .deck-card');
  if (postureCard) {
    const dialPath = path.join(ASSETS_DIR, 'prototype-radar-posture-dial.png');
    await postureCard.screenshot({ path: dialPath });
    await copyToAllAssetDirs('prototype-radar-posture-dial.png');
  }

  // 3. Migration Planner Tab (Bottom-half feature)
  console.log('[*] Capturing 3: prototype-migration-planner.png');
  await page.click('button[data-tab="planner"]');
  await new Promise(r => setTimeout(r, 600));
  // Scroll to show the nav tabs and the entire migration planner table clearly
  await page.evaluate(() => {
    const el = document.querySelector('.nav-tabs');
    if (el) el.scrollIntoView({ behavior: 'instant', block: 'start' });
  });
  await new Promise(r => setTimeout(r, 400));
  // We capture the planner card or the scrolled view
  const plannerCard = await page.$('#tab-planner .deck-card');
  if (plannerCard) {
    const planPath = path.join(ASSETS_DIR, 'prototype-migration-planner.png');
    await plannerCard.screenshot({ path: planPath });
    await copyToAllAssetDirs('prototype-migration-planner.png');
  }

  // 4. Auditor & Mosca Tab (Bottom-half feature)
  console.log('[*] Capturing 4: prototype-auditor-mosca.png');
  await page.click('button[data-tab="auditor"]');
  await new Promise(r => setTimeout(r, 600));
  const auditorCard = await page.$('#tab-auditor .deck-card');
  if (auditorCard) {
    const auditPath = path.join(ASSETS_DIR, 'prototype-auditor-mosca.png');
    await auditorCard.screenshot({ path: auditPath });
    await copyToAllAssetDirs('prototype-auditor-mosca.png');
  }

  // 5. Standards & CycloneDX 1.7 CBOM Tab (Bottom-half feature)
  console.log('[*] Capturing 5: prototype-cbom-preview.png');
  await page.click('button[data-tab="compliance"]');
  await new Promise(r => setTimeout(r, 800));
  const cbomCard = await page.$('#tab-compliance .deck-card');
  if (cbomCard) {
    const cbomPath = path.join(ASSETS_DIR, 'prototype-cbom-preview.png');
    await cbomCard.screenshot({ path: cbomPath });
    await copyToAllAssetDirs('prototype-cbom-preview.png');
  }

  // 6. Force-Directed Topology Map Tab (Bottom-half feature)
  console.log('[*] Capturing 6: prototype-topology-graph.png');
  await page.click('button[data-tab="topology"]');
  // Wait for canvas physics simulation to stabilize
  await new Promise(r => setTimeout(r, 1800));
  const topoCard = await page.$('#tab-topology .deck-card');
  if (topoCard) {
    const topoPath = path.join(ASSETS_DIR, 'prototype-topology-graph.png');
    await topoCard.screenshot({ path: topoPath });
    await copyToAllAssetDirs('prototype-topology-graph.png');
  }

  // 7. Sensor Array Tab (Bottom-half feature)
  console.log('[*] Capturing 7: prototype-sensor-array.png');
  await page.click('button[data-tab="sensors"]');
  await new Promise(r => setTimeout(r, 500));
  // Run sensors to populate their cards with real data
  await page.evaluate(async () => {
    if (typeof runSensor === 'function') {
      try { await runSensor('certificates'); } catch(e){}
      try { await runSensor('dependencies'); } catch(e){}
      try { await runSensor('verification'); } catch(e){}
    }
  });
  await new Promise(r => setTimeout(r, 1200));
  const sensorsTab = await page.$('#tab-sensors');
  if (sensorsTab) {
    const sensorPath = path.join(ASSETS_DIR, 'prototype-sensor-array.png');
    await sensorsTab.screenshot({ path: sensorPath });
    await copyToAllAssetDirs('prototype-sensor-array.png');
  }

  // 8. Evidence & Honesty Tab (Bottom-half feature)
  console.log('[*] Capturing 8: prototype-evidence-honesty.png');
  await page.click('button[data-tab="evidence"]');
  await new Promise(r => setTimeout(r, 600));
  const evidenceCard = await page.$('#tab-evidence .deck-card');
  if (evidenceCard) {
    const evPath = path.join(ASSETS_DIR, 'prototype-evidence-honesty.png');
    await evidenceCard.screenshot({ path: evPath });
    await copyToAllAssetDirs('prototype-evidence-honesty.png');
  }

  // 9. Executive HTML Report
  console.log('[*] Capturing 9: prototype-executive-report.png');
  await page.goto(`${TARGET_URL}/api/report/html`, { waitUntil: 'networkidle0', timeout: 30000 });
  await new Promise(r => setTimeout(r, 1000));
  const repPath = path.join(ASSETS_DIR, 'prototype-executive-report.png');
  await page.screenshot({ path: repPath });
  await copyToAllAssetDirs('prototype-executive-report.png');

  console.log('[✓] All prototype screenshots captured with high-fidelity focused views!');
  await browser.close();
})();

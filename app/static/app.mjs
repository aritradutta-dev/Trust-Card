import { buildAnalyzeRequest, chooseLink, detectContextFlags, extractUrls } from './context.mjs';

const input = document.querySelector('#message-input');
const count = document.querySelector('#char-count');
const preview = document.querySelector('#context-preview');
const detectedCount = document.querySelector('#detected-count');
const detectedCues = document.querySelector('#detected-cues');
const errorBox = document.querySelector('#input-error');
const picker = document.querySelector('#link-picker');
const options = document.querySelector('#link-options');
const resultRegion = document.querySelector('#result-region');
const findButton = document.querySelector('#find-links');
const localButton = document.querySelector('#check-local');
const clearButton = document.querySelector('#clear-input');
const sampleButton = document.querySelector('#try-sample');
const scanDialog = document.querySelector('#scan-consent');
const feedDialog = document.querySelector('#feed-consent');
const authDialog = document.querySelector('#auth-dialog');
const compareDialog = document.querySelector('#compare-dialog');
const scanProgress = document.querySelector('#scan-progress');

const cueLabels = {
  urgency: 'Urgency or pressure',
  credential_request: 'Credential request',
  payment_request: 'Payment request',
  personal_data_request: 'Personal information request',
};

let selectedUrl = '';
let selectedFlags = [];
let currentResult = null;
let resultNotice = '';
let currentUser = null;
let selectedScansForCompare = [];

// Event listeners for main checker
if (input) input.addEventListener('input', updateInputPreview);
if (findButton) findButton.addEventListener('click', findLinks);
if (localButton) {
  localButton.addEventListener('click', () => {
    const links = extractUrls(input.value);
    const choice = options.querySelector('input[name="selected-link"]:checked');
    selectedUrl = chooseLink(links, choice?.value);
    if (!selectedUrl) {
      showInputError('Choose one of the links first.');
      return;
    }
    checkLocally();
  });
}

function showToast(message, type = 'info') {
  const container = document.querySelector('#toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.dataset.type = type;
  const icon = document.createElement('span');
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = type === 'success' ? '✓' : type === 'error' ? '⚠' : '🛡️';
  const text = document.createElement('span');
  text.textContent = message;
  toast.append(icon, text);
  container.append(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

// Mobile menu toggle
const mobileMenuBtn = document.querySelector('#mobile-menu-btn');
const mobileNav = document.querySelector('#mobile-nav');
if (mobileMenuBtn && mobileNav) {
  mobileMenuBtn.addEventListener('click', () => {
    const isExpanded = mobileMenuBtn.getAttribute('aria-expanded') === 'true';
    mobileMenuBtn.setAttribute('aria-expanded', String(!isExpanded));
    mobileNav.hidden = isExpanded;
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !mobileNav.hidden) {
      mobileMenuBtn.setAttribute('aria-expanded', 'false');
      mobileNav.hidden = true;
    }
  });
  mobileNav.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', (e) => {
      mobileMenuBtn.setAttribute('aria-expanded', 'false');
      mobileNav.hidden = true;
      const targetView = link.getAttribute('data-tab-target');
      if (targetView) {
        e.preventDefault();
        switchView(targetView);
      }
    });
  });
}

// Platform View Tabs
function switchView(viewId) {
  document.querySelectorAll('.view-section').forEach((v) => {
    v.hidden = v.id !== viewId;
  });
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    const isActive = btn.getAttribute('data-view') === viewId;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });
  document.querySelectorAll('.top-nav a').forEach((link) => {
    const target = link.getAttribute('data-tab-target');
    if (target) link.classList.toggle('nav-active', target === viewId);
  });

  updateTabSlider();

  if (viewId === 'view-dashboard') loadDashboardStats();
  if (viewId === 'view-history') loadScanHistory();
  if (viewId === 'view-intel') searchThreatIntel();
  if (viewId === 'view-forum') loadForumThreads();
}

function updateTabSlider(immediate = false) {
  const nav = document.querySelector('.platform-tabs-nav');
  const slider = document.querySelector('.tab-slider-pill');
  const activeBtn = nav ? nav.querySelector('.tab-btn.active') : null;
  if (!nav || !slider || !activeBtn) return;

  const navRect = nav.getBoundingClientRect();
  const btnRect = activeBtn.getBoundingClientRect();
  const left = btnRect.left - navRect.left + nav.scrollLeft;
  const width = btnRect.width;

  if (immediate) {
    slider.style.transition = 'none';
  } else {
    slider.style.transition = 'transform 0.38s cubic-bezier(0.34, 1.35, 0.64, 1), width 0.38s cubic-bezier(0.34, 1.35, 0.64, 1), opacity 0.2s ease';
  }

  slider.style.transform = `translateX(${left}px)`;
  slider.style.width = `${width}px`;
  slider.style.opacity = '1';
  nav.classList.add('slider-ready');

  if (immediate) {
    requestAnimationFrame(() => {
      slider.style.transition = '';
    });
  }
}

function initTabSlider() {
  const nav = document.querySelector('.platform-tabs-nav');
  if (!nav) return;

  nav.addEventListener('mousemove', (e) => {
    const rect = nav.getBoundingClientRect();
    nav.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`);
    nav.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`);
  });

  nav.addEventListener('scroll', () => updateTabSlider(true), { passive: true });
  window.addEventListener('resize', () => updateTabSlider(true));

  setTimeout(() => updateTabSlider(true), 40);
  setTimeout(() => updateTabSlider(false), 220);
}

document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const view = btn.getAttribute('data-view');
    if (view) switchView(view);
  });
});

initTabSlider();

document.querySelectorAll('.top-nav a[data-tab-target]').forEach((link) => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const target = link.getAttribute('data-tab-target');
    if (target) switchView(target);
  });
});

document.querySelectorAll('a[href="#how-it-works"]').forEach((link) => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    switchView('view-checker');
    const el = document.getElementById('how-it-works');
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  });
});

document.querySelectorAll('a[href="#contact"]').forEach((link) => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const el = document.getElementById('contact');
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  });
});

// Clear & Sample buttons
if (clearButton) {
  clearButton.addEventListener('click', () => {
    input.value = '';
    selectedUrl = '';
    selectedFlags = [];
    currentResult = null;
    resultNotice = '';
    count.textContent = '0 / 12,000';
    preview.hidden = true;
    picker.hidden = true;
    resultRegion.hidden = true;
    resultRegion.replaceChildren();
    errorBox.hidden = true;
    input.focus();
    showToast('Input cleared.', 'info');
  });
}

if (sampleButton) {
  sampleButton.addEventListener('click', () => {
    input.value = 'URGENT: Verify your account now to avoid suspension. Send your OTP and pay the ₹99 verification fee: https://secure-account-check.example/verify';
    updateInputPreview();
    input.focus();
    showToast('Sample message with payment request loaded.', 'success');
  });
}

for (const chip of document.querySelectorAll('.example-chip')) {
  chip.addEventListener('click', () => {
    const url = chip.getAttribute('data-example-url');
    if (url) {
      input.value = url;
      updateInputPreview();
      input.focus();
      showToast(`Example link loaded: ${url}`, 'info');
    }
  });
}

// Scan consent dialog
document.querySelector('#approve-scan')?.addEventListener('click', async () => {
  const ctRdapConsent = Boolean(document.querySelector('#consent-ct-rdap')?.checked);
  scanDialog?.close();
  await analyze('full_scan', true, ctRdapConsent);
});
document.querySelector('#decline-scan')?.addEventListener('click', declineLiveScan);
document.querySelector('[data-close-dialog="scan-consent"]')?.addEventListener('click', declineLiveScan);
scanDialog?.addEventListener('cancel', (event) => {
  event.preventDefault();
  declineLiveScan();
});

// Feed refresh dialog
document.querySelector('#refresh-feeds')?.addEventListener('click', () => feedDialog?.showModal());
document.querySelector('#cancel-feeds')?.addEventListener('click', () => feedDialog?.close());
document.querySelector('[data-close-dialog="feed-consent"]')?.addEventListener('click', () => feedDialog?.close());
document.querySelector('#approve-feeds')?.addEventListener('click', refreshFeeds);

function updateInputPreview() {
  count.textContent = `${input.value.length.toLocaleString()} / 12,000`;
  errorBox.hidden = true;
  picker.hidden = true;
  selectedUrl = '';
  selectedFlags = [];
  currentResult = null;
  resultNotice = '';
  resultRegion.hidden = true;
  resultRegion.replaceChildren();
  const links = extractUrls(input.value);
  const flags = detectContextFlags(input.value);
  preview.hidden = !input.value.trim();
  detectedCount.textContent = links.length ? `${links.length} ${links.length === 1 ? 'link' : 'links'} found` : 'No links found yet';
  renderCuePills(detectedCues, flags, 'No common pressure cues found');
}

function findLinks() {
  const links = extractUrls(input.value);
  if (!links.length) {
    showInputError('We could not find an HTTP or HTTPS link. Paste a link or a message that contains one.');
    showToast('No valid link found. Please enter an HTTP or HTTPS URL.', 'error');
    return;
  }
  selectedFlags = detectContextFlags(input.value);
  if (links.length === 1) {
    selectedUrl = links[0];
    checkLocally();
    return;
  }
  showLinkOptions(links);
}

function showInputError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function showLinkOptions(links) {
  options.replaceChildren();
  document.querySelector('#picker-count').textContent = `${links.length} links`;
  renderCuePills(document.querySelector('#selection-cues'), selectedFlags, 'No common pressure cues found');

  for (const [index, url] of links.entries()) {
    const label = document.createElement('label');
    label.className = 'link-option';
    const radio = document.createElement('input');
    radio.type = 'radio';
    radio.name = 'selected-link';
    radio.value = url;
    const body = document.createElement('span');
    body.className = 'link-option-body';
    const link = document.createElement('code');
    link.textContent = url;
    const indexLabel = document.createElement('small');
    indexLabel.textContent = `Link ${index + 1}`;
    body.append(indexLabel, link);
    label.append(radio, body);
    options.append(label);
  }

  options.querySelector('input[name="selected-link"]').checked = true;
  picker.hidden = false;
  errorBox.hidden = true;
  picker.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function checkLocally() {
  picker.hidden = true;
  errorBox.hidden = true;
  await analyze('local', false);
}

function declineLiveScan() {
  scanDialog?.close();
  resultNotice = 'Live scan not run. Your local-only result is still available.';
  if (currentResult) renderResult(currentResult);
}

function setScanProgress(step) {
  if (!scanProgress) return;
  scanProgress.hidden = false;
  scanProgress.querySelectorAll('.progress-step').forEach((el) => {
    const s = Number.parseInt(el.getAttribute('data-step') || '0', 10);
    el.classList.toggle('done', s < step);
    el.classList.toggle('active', s === step);
  });
}

function finishScanProgress() {
  if (!scanProgress) return;
  scanProgress.querySelectorAll('.progress-step').forEach((el) => {
    el.classList.remove('active');
    el.classList.add('done');
  });
  setTimeout(() => {
    scanProgress.hidden = true;
  }, 1200);
}

async function analyze(mode, consent, ctRdapConsent = false) {
  input.disabled = true;
  findButton.disabled = true;
  clearButton.disabled = true;
  sampleButton.disabled = true;
  if (localButton) localButton.disabled = true;
  resultRegion.hidden = false;
  resultRegion.replaceChildren(makeStatus('Checking this link across threat intelligence and security pillars…'));
  resultNotice = '';

  setScanProgress(1);
  setTimeout(() => setScanProgress(2), 250);
  if (mode === 'full_scan') {
    setTimeout(() => setScanProgress(3), 500);
    setTimeout(() => setScanProgress(4), 800);
    setTimeout(() => setScanProgress(5), 1100);
  } else {
    setTimeout(() => setScanProgress(5), 450);
  }

  try {
    const response = await fetch('/api/v1/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildAnalyzeRequest(selectedUrl, mode, consent, selectedFlags, ctRdapConsent)),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(apiError(data, 'The link could not be checked.'));
    currentResult = data;
    finishScanProgress();
    renderResult(data);
    resultRegion.scrollIntoView({ behavior: 'smooth', block: 'start' });
    showToast(mode === 'local' ? 'Local security check completed.' : 'Live security scan completed.', 'success');
  } catch (error) {
    if (scanProgress) scanProgress.hidden = true;
    resultRegion.replaceChildren(makeStatus(error.message || 'The check could not be completed.'));
    showToast(error.message || 'The check could not be completed.', 'error');
  } finally {
    input.disabled = false;
    findButton.disabled = false;
    clearButton.disabled = false;
    sampleButton.disabled = false;
    if (localButton) localButton.disabled = false;
  }
}

function makeStatus(message) {
  const status = document.createElement('div');
  status.className = 'result-card empty-state';
  status.setAttribute('role', 'status');
  status.textContent = message;
  return status;
}

function getHumanFriendlyHeadline(verdict, score) {
  if (verdict === 'known_threat') {
    return '🚨 High-Risk Threat — Do Not Open This Link';
  }
  if (verdict === 'suspicious') {
    return score >= 60 ? '⚠️ High Suspicion — Phishing Indicators Observed' : '⚠️ Suspicious Activity — Caution Required';
  }
  if (verdict === 'caution') {
    return '⚠️ Technical Trust Failure — Cryptographic Warning';
  }
  if (verdict === 'no_strong_warning') {
    return '🛡️ No Known Threats Detected Across Tested Pillars';
  }
  if (verdict === 'not_enough_info') {
    return 'ℹ️ Limited Threat Data Available for this Domain';
  }
  return '❓ Scan Incomplete — Review Available Signals';
}

function renderResult(data) {
  currentResult = data;
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const card = document.createElement('article');
  const verdictClass = {
    known_threat: 'verdict-known',
    suspicious: 'verdict-suspicious',
    caution: 'verdict-caution',
    no_strong_warning: 'verdict-no-warning',
    not_enough_info: 'verdict-not-enough',
    unable_to_check: 'verdict-unable',
  }[data.verdict] || 'verdict-unable';
  card.className = `result-card trust-card ${verdictClass} result-card-modern`;

  // 1. Calculate Score & Gauge Theme
  const score = data.scoring?.score ?? (data.verdict === 'known_threat' ? 100 : data.verdict === 'suspicious' ? 65 : data.verdict === 'caution' ? 40 : 10);
  const gaugeColor = score >= 70 ? '#A83232' : score >= 45 ? '#D95D39' : score >= 20 ? '#D4A359' : '#778D7A';
  const circumference = 2 * Math.PI * 40; // r=40
  const strokeDashoffset = Math.max(0, circumference - (score / 100) * circumference);

  // 2. Executive Hero Banner
  const hero = document.createElement('div');
  hero.className = 'result-hero-banner';

  // SVG Gauge
  const gaugeWrap = document.createElement('div');
  gaugeWrap.className = 'threat-gauge-wrapper';
  gaugeWrap.innerHTML = `
    <svg class="threat-gauge-svg" width="104" height="104" viewBox="0 0 96 96" aria-hidden="true">
      <circle class="gauge-bg" cx="48" cy="48" r="40" stroke="rgba(212, 196, 168, 0.45)" stroke-width="7" fill="none" />
      <circle class="gauge-meter" cx="48" cy="48" r="40" stroke="${gaugeColor}" stroke-width="7" stroke-dasharray="${circumference.toFixed(1)}" stroke-dashoffset="${strokeDashoffset.toFixed(1)}" stroke-linecap="round" fill="none" transform="rotate(-90 48 48)" />
    </svg>
    <div class="gauge-center">
      <span class="gauge-score">${score}</span>
      <span class="gauge-scale">/100</span>
      <span class="gauge-label">THREAT</span>
    </div>
  `;

  // Info Column
  const infoCol = document.createElement('div');
  infoCol.className = 'result-hero-info';

  const badgeRow = document.createElement('div');
  badgeRow.className = 'hero-tag-row';
  
  const verdictPill = document.createElement('span');
  verdictPill.className = `verdict-pill verdict-pill-${data.verdict}`;
  const iconSymbol = data.verdict === 'known_threat' || data.verdict === 'suspicious' ? '🚨' : data.verdict === 'caution' ? '⚠️' : data.verdict === 'no_strong_warning' ? '🛡️' : '❓';
  verdictPill.innerHTML = `<span class="pill-dot"></span> ${iconSymbol} ${verdictTitle(data.verdict)}`;
  badgeRow.append(verdictPill);

  if (data.target_category) {
    const targetPill = document.createElement('span');
    targetPill.className = 'hero-target-pill';
    targetPill.textContent = `Target: ${titleCase(data.target_category)}`;
    badgeRow.append(targetPill);
  }

  const timePill = document.createElement('span');
  timePill.className = 'hero-time';
  timePill.textContent = `Checked ${formatDate(data.checked_at)}`;
  badgeRow.append(timePill);

  const headline = document.createElement('h2');
  headline.className = 'hero-headline';
  headline.textContent = getHumanFriendlyHeadline(data.verdict, score);

  const summary = document.createElement('p');
  summary.className = 'hero-summary';
  summary.textContent = verdictSummary(data.verdict);

  const urlChip = document.createElement('div');
  urlChip.className = 'hero-url-chip';
  const isHttps = selectedUrl.startsWith('https');
  urlChip.innerHTML = `
    <span class="url-scheme-badge ${isHttps ? 'scheme-https' : 'scheme-http'}">${isHttps ? '🔒 HTTPS' : '⚠️ HTTP'}</span>
    <span class="url-text" title="${selectedUrl}">${selectedUrl}</span>
    <button type="button" class="copy-url-btn" title="Copy URL" aria-label="Copy inspected URL">📋 Copy</button>
  `;
  const copyBtn = urlChip.querySelector('.copy-url-btn');
  copyBtn?.addEventListener('click', () => {
    navigator.clipboard?.writeText(selectedUrl);
    copyBtn.textContent = '✓ Copied';
    setTimeout(() => { copyBtn.textContent = '📋 Copy'; }, 2000);
  });

  infoCol.append(badgeRow, headline, summary, urlChip);
  hero.append(gaugeWrap, infoCol);
  card.append(hero);

  // 3. High-Visibility Safety Callout
  const callout = document.createElement('div');
  const isDanger = data.verdict === 'known_threat' || data.verdict === 'suspicious';
  callout.className = `hero-action-callout ${isDanger ? 'callout-danger' : data.verdict === 'caution' ? 'callout-warning' : 'callout-safe'}`;
  const calloutSymbol = isDanger ? '🛑' : data.verdict === 'caution' ? '⚠️' : '✅';
  const calloutLead = isDanger ? 'Immediate Safety Advice: Avoid this site completely.' : data.verdict === 'caution' ? 'Caution Advised: Technical trust issues detected.' : 'Safe Practice: No active threat signatures found.';
  const calloutDetail = data.next_steps && data.next_steps[0] ? data.next_steps[0] : 'Use official mobile applications or verified bookmarked URLs rather than interacting with unverified links.';
  callout.innerHTML = `
    <span class="callout-icon">${calloutSymbol}</span>
    <div class="callout-text">
      <strong>${calloutLead}</strong>
      <span>${calloutDetail}</span>
    </div>
  `;
  card.append(callout);

  // 4. Quick Vitals Bar (Single-Row Strip)
  const vitals = document.createElement('div');
  vitals.className = 'result-vitals-strip';
  const freshest = freshestFeed(data.feed_status || []);
  vitals.innerHTML = `
    <div class="vital-item">
      <span class="vital-label">CONFIDENCE</span>
      <strong class="vital-value">${confidenceLabel(data.confidence)}</strong>
      <small class="vital-hint">Evidence depth</small>
    </div>
    <div class="vital-item">
      <span class="vital-label">COVERAGE</span>
      <strong class="vital-value">${coverageShortLabel(data.coverage)}</strong>
      <small class="vital-hint">${coverageDetail(data)}</small>
    </div>
    <div class="vital-item">
      <span class="vital-label">THREAT DATA</span>
      <strong class="vital-value">${data.feed_stale ? 'Stale' : 'Current'}</strong>
      <small class="vital-hint">${freshest ? formatDate(freshest) : '3 verified feeds'}</small>
    </div>
    <div class="vital-item">
      <span class="vital-label">SECURITY PILLARS</span>
      <strong class="vital-value">${data.scoring ? data.scoring.checked_count : 3} of 5 Active</strong>
      <small class="vital-hint">Multi-pillar audit</small>
    </div>
  `;
  card.append(vitals);

  // 5. AI Security Co-Pilot Threat Synthesis (if available)
  if (data.ai_explanation) {
    const aiCard = document.createElement('section');
    aiCard.className = 'result-ai-card';
    const vectorsHtml = data.ai_explanation.attack_techniques?.length
      ? `<div class="ai-vectors-row"><span class="vectors-title">Detected Attack Vectors:</span><div class="vectors-list">${data.ai_explanation.attack_techniques.map(t => `<span class="vector-chip">#${t}</span>`).join('')}</div></div>`
      : '';
    aiCard.innerHTML = `
      <div class="ai-card-header">
        <span class="ai-robot-badge">🤖 AI Security Co-Pilot Analysis</span>
        <span class="ai-source-tag">${data.ai_explanation.source || 'Neural Synthesis'}</span>
      </div>
      <p class="ai-card-body">${data.ai_explanation.summary}</p>
      ${vectorsHtml}
    `;
    card.append(aiCard);
  }

  // 6. Progressive Disclosure Tabs Navigation (The Clutter-Killer!)
  const tabNav = document.createElement('div');
  tabNav.className = 'result-tabs-segmented';
  tabNav.setAttribute('role', 'tablist');

  const tabDefs = [
    { id: 'tab-overview', icon: '📋', label: 'Overview & Safety Plan', active: true },
    { id: 'tab-pillars', icon: '🛡️', label: '5 Security Pillars', badge: data.scoring ? `${data.scoring.score}/100` : null },
    { id: 'tab-findings', icon: '🔬', label: 'Technical Evidence', badge: `${findings.length} signal${findings.length === 1 ? '' : 's'}` },
  ];
  if (data.certificate) {
    tabDefs.push({ id: 'tab-crypto', icon: '🔒', label: 'TLS & Certificate' });
  }

  tabDefs.forEach((t) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `result-tab-btn ${t.active ? 'active' : ''}`;
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', t.active ? 'true' : 'false');
    btn.setAttribute('data-target-pane', t.id);
    btn.innerHTML = `<span>${t.icon}</span> <span>${t.label}</span>${t.badge ? `<span class="res-tab-chip">${t.badge}</span>` : ''}`;
    tabNav.append(btn);
  });
  card.append(tabNav);

  // PANE CONTAINER
  const paneContainer = document.createElement('div');
  paneContainer.className = 'result-panes-container';

  // --- PANE 1: Overview & Safety Plan ---
  const paneOverview = document.createElement('div');
  paneOverview.id = 'tab-overview';
  paneOverview.className = 'result-tab-pane active';

  // Overview Grid: Left = Top Observed Signals, Right = Safety Checklist
  const overviewGrid = document.createElement('div');
  overviewGrid.className = 'overview-cards-grid';

  // Left card: Why was this result reached?
  const signalsCard = document.createElement('div');
  signalsCard.className = 'overview-subcard';
  signalsCard.innerHTML = `
    <div class="subcard-header">
      <span class="subcard-icon">🔍</span>
      <h4>Why this result?</h4>
      <span class="subcard-badge">${findings.length} observed</span>
    </div>
  `;
  if (findings.length > 0) {
    const sigList = document.createElement('div');
    sigList.className = 'quick-signal-list';
    findings.slice(0, 4).forEach((f) => {
      const item = document.createElement('div');
      item.className = 'quick-signal-item';
      const mark = f.severity === 'high' ? '🚨' : f.severity === 'medium' ? '⚠️' : 'ℹ️';
      item.innerHTML = `
        <span class="signal-glyph">${mark}</span>
        <div>
          <strong>${f.category === 'known_threat' ? 'Threat Intelligence Match' : titleCase(f.category || 'Warning')}</strong>
          <p>${f.explanation || f.summary || 'Signal observed during analysis.'}</p>
        </div>
      `;
      sigList.append(item);
    });
    if (findings.length > 4) {
      const moreNote = document.createElement('button');
      moreNote.type = 'button';
      moreNote.className = 'switch-to-findings-btn';
      moreNote.textContent = `+ View all ${findings.length} technical signals →`;
      moreNote.addEventListener('click', () => {
        switchResultTab('tab-findings');
      });
      sigList.append(moreNote);
    }
    signalsCard.append(sigList);
  } else {
    signalsCard.innerHTML += `<p class="empty-state-note">No threat signatures or malicious patterns were observed across tested pillars.</p>`;
  }

  // Right card: Action Checklist
  const nextStepsCard = document.createElement('div');
  nextStepsCard.className = 'overview-subcard next-steps-subcard';
  nextStepsCard.innerHTML = `
    <div class="subcard-header">
      <span class="subcard-icon">🛡️</span>
      <h4>A Safer Next Step</h4>
      <span class="subcard-badge">Checklist</span>
    </div>
  `;
  const nextList = document.createElement('ul');
  nextList.className = 'checklist-ul';
  (data.next_steps || ['Do not enter passwords, OTPs, or financial information.', 'Verify directly via the organisation\'s official app or bookmarked website.']).forEach((step) => {
    const li = document.createElement('li');
    li.innerHTML = `<span class="check-bullet">✓</span> <span>${step}</span>`;
    nextList.append(li);
  });
  nextStepsCard.append(nextList);

  overviewGrid.append(signalsCard, nextStepsCard);
  paneOverview.append(overviewGrid);

  // Redirect chain if present
  if (Array.isArray(data.redirect_hosts) && data.redirect_hosts.length > 1) {
    const redirectBox = document.createElement('div');
    redirectBox.className = 'redirect-trail-box';
    redirectBox.innerHTML = `
      <span class="trail-title">🔄 Redirect Journey (${data.redirect_hosts.length} hops):</span>
      <div class="trail-chain">${data.redirect_hosts.map((h, i) => `<span class="trail-node">${h}</span>${i < data.redirect_hosts.length - 1 ? '<span class="trail-arrow">→</span>' : ''}`).join('')}</div>
    `;
    paneOverview.append(redirectBox);
  }

  // Coverage Note
  const coverageP = document.createElement('p');
  coverageP.className = 'coverage-note';
  coverageP.textContent = coverageExplanation(data);
  paneOverview.append(coverageP);

  paneContainer.append(paneOverview);

  // --- PANE 2: Security Pillars ---
  const panePillars = document.createElement('div');
  panePillars.id = 'tab-pillars';
  panePillars.className = 'result-tab-pane';

  if (data.scoring && data.scoring.pillars) {
    const pillarsGrid = document.createElement('div');
    pillarsGrid.className = 'pillars-cards-grid';

    for (const [, pillar] of Object.entries(data.scoring.pillars)) {
      const pCard = document.createElement('div');
      pCard.className = 'pillar-feature-card';

      const pScore = pillar.score ?? (pillar.status === 'alert' ? 100 : pillar.status === 'attention' ? 50 : 0);
      const pColor = pillar.status === 'alert' ? '#A83232' : pillar.status === 'attention' ? '#D4A359' : pillar.status === 'clear' ? '#778D7A' : '#415A77';

      pCard.innerHTML = `
        <div class="pillar-top-row">
          <strong class="pillar-title">${pillar.name}</strong>
          <span class="pillar-status-chip status-${pillar.status}">${pillar.status === 'not_checked' ? 'Not Checked' : pillar.status}</span>
        </div>
        <div class="pillar-meter-bar" title="Risk: ${pScore}/100">
          <div class="meter-fill" style="width: ${pScore}%; background: ${pColor};"></div>
        </div>
        <div class="pillar-risk-row">
          <span class="pillar-why-text">${pillar.why}</span>
          ${pillar.status !== 'not_checked' ? `<span class="pillar-score-val" style="color: ${pColor};">Risk: ${pScore}/100</span>` : ''}
        </div>
      `;

      if (Array.isArray(pillar.findings) && pillar.findings.length > 0) {
        const toggle = document.createElement('details');
        toggle.className = 'pillar-signals-details';
        toggle.innerHTML = `
          <summary>${pillar.findings.length} signal${pillar.findings.length === 1 ? '' : 's'} observed</summary>
          <ul>${pillar.findings.map(f => `<li>${f.summary || f.explanation || f.id}</li>`).join('')}</ul>
        `;
        pCard.append(toggle);
      }
      pillarsGrid.append(pCard);
    }
    panePillars.append(pillarsGrid);
  } else {
    panePillars.innerHTML = `<p class="empty-state-note">Security pillar evaluation data is not available for this scan mode.</p>`;
  }
  paneContainer.append(panePillars);

  // --- PANE 3: Technical Findings ---
  const paneFindings = document.createElement('div');
  paneFindings.id = 'tab-findings';
  paneFindings.className = 'result-tab-pane';

  if (findings.length > 0) {
    const findingsList = document.createElement('div');
    findingsList.className = 'findings-deck';
    findings.forEach((f) => {
      const fCard = document.createElement('div');
      fCard.className = `finding-card severity-${f.severity || 'low'}`;
      const fSeverity = (f.severity || 'info').toUpperCase();
      fCard.innerHTML = `
        <div class="finding-card-head">
          <div class="finding-title-row">
            <span class="severity-badge sev-${f.severity || 'low'}">${fSeverity}</span>
            <strong class="finding-title">${f.category === 'known_threat' ? 'Confirmed Threat Intelligence Match' : titleCase(f.category || 'Finding')}</strong>
          </div>
          <span class="finding-source-tag">${f.source || 'Local Analysis'}${f.observed_at ? ` · ${formatDate(f.observed_at)}` : ''}</span>
        </div>
        <p class="finding-explanation">${f.explanation || f.summary || 'A security signal was observed.'}</p>
        ${f.potential_impact ? `<div class="finding-impact"><strong>Potential Impact:</strong> ${f.potential_impact}</div>` : ''}
        ${f.recommended_remediation ? `<div class="finding-remediation"><strong>Recommended Remediation:</strong> ${f.recommended_remediation}</div>` : ''}
      `;
      findingsList.append(fCard);
    });
    paneFindings.append(findingsList);
  } else {
    paneFindings.innerHTML = `<div class="clean-findings-state"><span class="clean-icon">🛡️</span><h4>No Technical Threat Findings</h4><p>All automated heuristics and signature feeds returned zero warnings.</p></div>`;
  }
  paneContainer.append(paneFindings);

  // --- PANE 4: TLS & Certificate ---
  if (data.certificate) {
    const paneCrypto = document.createElement('div');
    paneCrypto.id = 'tab-crypto';
    paneCrypto.className = 'result-tab-pane';

    const certCard = document.createElement('div');
    certCard.className = 'crypto-specs-card';
    certCard.innerHTML = `
      <div class="crypto-specs-head">
        <h4>🔒 Cryptographic Trust & Certificate Infrastructure</h4>
        <span class="crypto-badge">${data.certificate.key_type || 'TLS'} (${data.certificate.key_size || 0} bits)</span>
      </div>
      <div class="cert-grid">
        <div class="cert-field"><span class="cert-field-name">Subject</span><span class="cert-field-val">${data.certificate.subject || 'None'}</span></div>
        <div class="cert-field"><span class="cert-field-name">Issuer (CA)</span><span class="cert-field-val">${data.certificate.issuer || 'None'}</span></div>
        <div class="cert-field"><span class="cert-field-name">SANs</span><span class="cert-field-val">${Array.isArray(data.certificate.sans) && data.certificate.sans.length ? data.certificate.sans.join(', ') : 'None'}</span></div>
        <div class="cert-field"><span class="cert-field-name">Valid From</span><span class="cert-field-val">${formatDate(data.certificate.valid_from)}</span></div>
        <div class="cert-field"><span class="cert-field-name">Valid Until</span><span class="cert-field-val">${formatDate(data.certificate.valid_to)}</span></div>
        <div class="cert-field"><span class="cert-field-name">Key Specifications</span><span class="cert-field-val">${data.certificate.key_type || 'Unknown'} · ${data.certificate.key_size || 0} bits</span></div>
        <div class="cert-field"><span class="cert-field-name">Signature Algorithm</span><span class="cert-field-val">${data.certificate.signature_algorithm || 'Unknown'}</span></div>
        <div class="cert-field"><span class="cert-field-name">CT Timestamps (SCT)</span><span class="cert-field-val">${data.certificate.sct_count || 0} embedded timestamp(s)</span></div>
      </div>
    `;
    paneCrypto.append(certCard);
    paneContainer.append(paneCrypto);
  }

  card.append(paneContainer);

  // Tab switching logic
  function switchResultTab(targetId) {
    tabNav.querySelectorAll('.result-tab-btn').forEach((b) => {
      const match = b.getAttribute('data-target-pane') === targetId;
      b.classList.toggle('active', match);
      b.setAttribute('aria-selected', match ? 'true' : 'false');
    });
    paneContainer.querySelectorAll('.result-tab-pane').forEach((p) => {
      p.classList.toggle('active', p.id === targetId);
    });
  }

  tabNav.querySelectorAll('.result-tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-target-pane');
      if (target) switchResultTab(target);
    });
  });

  // 7. Result Notices (if any)
  if (resultNotice) {
    const notice = document.createElement('div');
    notice.className = 'result-notice-toast';
    notice.innerHTML = `<span>ℹ️</span> <span>${resultNotice}</span>`;
    card.append(notice);
  }

  // 8. Result Action Dock at the bottom
  const dock = document.createElement('div');
  dock.className = 'result-action-dock';

  if (data.scan_id) {
    const pdfBtn = makeButton('🖨️ Download PDF Report', 'dock-btn btn-pdf', () => {
      window.open(`/scans/${data.scan_id}/report`, '_blank');
    });
    dock.append(pdfBtn);
  }

  if (data.coverage === 'local_only' || (data.scan_error && data.scan_error !== 'scanner_unavailable')) {
    const liveScanBtn = makeButton('🔬 Run Optional Live Deep Scan', 'dock-btn btn-live', () => {
      document.querySelector('#consent-host').textContent = selectedUrl;
      const cb = document.querySelector('#consent-ct-rdap');
      if (cb) cb.checked = false;
      scanDialog?.showModal();
    });
    dock.append(liveScanBtn);
  }

  if (data.verdict !== 'known_threat') {
    const reportGroup = document.createElement('div');
    reportGroup.className = 'dock-report-group';
    const category = document.createElement('select');
    category.className = 'dock-report-select';
    category.setAttribute('aria-label', 'Choose report category');
    category.innerHTML = `
      <option value="" disabled selected>Report this threat...</option>
      <option value="phishing">Phishing</option>
      <option value="malware">Malware</option>
      <option value="fake_banking">Fake Banking Portal</option>
      <option value="fraudulent_payment">Fraudulent Payment</option>
      <option value="fake_recruitment">Fake Recruitment</option>
      <option value="impersonation">Brand Impersonation</option>
      <option value="other">Other</option>
    `;
    const reportButton = makeButton('🚨 Submit Threat Report', 'dock-btn btn-report', () => {
      if (category.value) submitReport(category.value);
    });
    reportButton.disabled = true;
    category.addEventListener('change', () => {
      reportButton.disabled = !category.value;
    });
    reportGroup.append(category, reportButton);
    dock.append(reportGroup);
  }

  card.append(dock);
  resultRegion.replaceChildren(card);
  resultRegion.hidden = false;
}

function makeMetric(label, value, detail) {
  const metric = document.createElement('div');
  metric.className = 'metric';
  const heading = document.createElement('span');
  heading.textContent = label;
  const strong = document.createElement('strong');
  strong.textContent = value;
  const note = document.createElement('small');
  note.textContent = detail;
  metric.append(heading, strong, note);
  return metric;
}

function makeFinding(finding) {
  const row = document.createElement('div');
  row.className = 'finding';
  const icon = document.createElement('span');
  icon.className = 'finding-mark';
  icon.dataset.severity = finding.severity || 'low';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = finding.severity === 'high' ? '!' : finding.severity === 'medium' ? '•' : 'i';
  const body = document.createElement('div');
  const title = document.createElement('strong');
  title.textContent = finding.category === 'known_threat' ? 'Threat intelligence match' : titleCase(finding.category || 'Finding');
  const explanation = document.createElement('p');
  explanation.textContent = finding.explanation || finding.summary || 'A signal was observed.';
  const source = document.createElement('small');
  source.textContent = `${finding.source || 'Local check'}${finding.observed_at ? ` · Observed ${formatDate(finding.observed_at)}` : ''}`;
  body.append(title, explanation, source);
  row.append(icon, body);
  return row;
}

async function submitReport(category) {
  if (!currentResult?.scan_id) return;
  try {
    const response = await fetch('/api/v1/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: currentResult.scan_id, category }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(apiError(data, 'The report could not be submitted.'));
    resultNotice = data.message;
    renderResult(currentResult);
    showToast(data.message || 'Report submitted for review.', 'success');
  } catch (error) {
    resultNotice = error.message;
    renderResult(currentResult);
    showToast(error.message || 'Report could not be submitted.', 'error');
  }
}

async function refreshFeeds() {
  const button = document.querySelector('#approve-feeds');
  if (!button) return;
  button.disabled = true;
  button.textContent = 'Refreshing…';
  try {
    const response = await fetch('/api/v1/intel/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ providers: ['PhishTank', 'URLhaus', 'OpenPhish'] }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(apiError(data, 'The feeds could not be refreshed.'));
    feedDialog?.close();
    updateFeedStatus(data);
    const updated = data.results.filter((item) => item.updated).length;
    resultNotice = updated ? `${updated} threat feed${updated === 1 ? '' : 's'} refreshed.` : 'Feeds could not be refreshed. Previous saved data remains available.';
    if (currentResult) renderResult(currentResult);
    showToast(resultNotice, updated ? 'success' : 'info');
  } catch (error) {
    feedDialog?.close();
    const summary = document.querySelector('#feed-summary');
    if (summary) summary.textContent = error.message;
    showToast(error.message || 'Feed refresh failed.', 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Refresh feeds';
  }
}

function updateFeedStatus(data) {
  const status = document.querySelector('#feed-status');
  if (!status) return;
  status.replaceChildren();
  for (const item of data.providers || []) {
    const chip = document.createElement('span');
    chip.className = 'feed-chip';
    const state = !item.available ? 'not loaded' : item.stale ? 'stale' : `updated ${formatDate(item.updated_at)}`;
    const label = item.source === 'Demo seed' ? 'Demo data, not real threat intelligence' : item.source;
    chip.textContent = `${label} · ${state}`;
    status.append(chip);
  }
  const summary = document.querySelector('#feed-summary');
  if (summary) {
    summary.textContent = data.stale
      ? 'One or more feeds are missing or stale. A no-match is not a clean bill of health.'
      : 'Threat feeds are up to date.';
  }
}

function renderCuePills(container, flags, emptyMessage) {
  if (!container) return;
  container.replaceChildren();
  if (!flags.length) {
    const empty = document.createElement('span');
    empty.className = 'cue-empty';
    empty.textContent = emptyMessage;
    container.append(empty);
    return;
  }
  for (const flag of flags) {
    const pill = document.createElement('span');
    pill.className = 'cue-pill';
    pill.textContent = cueLabels[flag] || titleCase(flag);
    container.append(pill);
  }
}

function makeButton(text, className, action) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = text;
  button.addEventListener('click', action);
  return button;
}

function verdictTitle(verdict) {
  return ({
    known_threat: 'Known threat',
    suspicious: 'Suspicious',
    caution: 'Caution: technical problems found',
    no_strong_warning: 'No strong warning found',
    not_enough_info: 'Not enough information yet',
    unable_to_check: 'Unable to check',
  })[verdict] || 'Check result';
}

function verdictSummary(verdict) {
  return ({
    known_threat: 'This link matched a confirmed threat source or an approved local report.',
    suspicious: 'Several signals deserve attention before you interact with this site.',
    caution: 'Technical problems were found with this site. Verify through an official channel before proceeding.',
    no_strong_warning: 'The checks completed without finding a strong warning. Keep using your judgment.',
    not_enough_info: 'Nothing matched local data, but no live check has run and threat data is missing or stale.',
    unable_to_check: 'There is not enough completed evidence to give a useful verdict.',
  })[verdict] || 'Review the evidence and choose a cautious next step.';
}

function confidenceLabel(value) {
  return ({ high: 'High', medium: 'Moderate', low: 'Limited' })[value] || 'Limited';
}

function coverageShortLabel(value) {
  return ({ local_only: 'Local only', partial: 'Partial', full: 'Full' })[value] || 'Limited';
}

function coverageDetail(data) {
  if (data.coverage === 'local_only') return 'No site connection';
  if (data.coverage === 'partial') return 'Some checks unavailable';
  return 'Live checks and feeds current';
}

function coverageExplanation(data) {
  if (data.scan_error === 'scanner_unavailable') {
    return data.feed_stale
      ? 'No live site connection was made because the scanner is unavailable. Some local threat feeds are missing or stale.'
      : 'No live site connection was made because the scanner is unavailable. Only local checks were available.';
  }
  if (data.coverage === 'local_only') {
    return data.feed_stale
      ? 'Local-only check: no connection was made to the selected site, and some threat data is missing or stale.'
      : 'Local-only check: no connection was made to the selected site.';
  }
  const uncertainty = data.verdict === 'no_strong_warning'
    ? ' A result without a warning does not establish that the link is legitimate.'
    : '';
  if (data.coverage === 'partial') {
    const reasons = [];
    if (data.scan_error || data.scan_coverage === 'partial') reasons.push('Some live page checks were skipped or could not finish');
    if (data.feed_stale) reasons.push('some local threat feeds are missing or stale');
    if (!reasons.length) reasons.push('one or more checks had limited coverage');
    return `${reasons.join('; ')}.${uncertainty}`;
  }
  return `The selected site and permitted redirects were inspected.${uncertainty}`;
}

function freshestFeed(rows) {
  const dates = rows.map((row) => Date.parse(row.updated_at || '')).filter(Number.isFinite);
  return dates.length ? new Date(Math.max(...dates)).toISOString() : '';
}

function formatDate(value) {
  if (!value) return 'time unavailable';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? 'time unavailable' : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function titleCase(value) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function apiError(data, fallback) {
  if (data?.detail === 'scanner_unavailable') return 'This local install is not connected to the scanner service.';
  if (Array.isArray(data?.detail)) return 'Use an HTTP or HTTPS link on port 80 or 443.';
  return typeof data?.detail === 'string' ? data.detail.replaceAll('_', ' ') : fallback;
}

// ---------------------------------------------------------------------------
// 1. Dashboard Analytics Implementation
// ---------------------------------------------------------------------------
async function loadDashboardStats() {
  try {
    const res = await fetch('/api/v1/dashboard/stats');
    if (!res.ok) return;
    const stats = await res.json();

    document.querySelector('#kpi-total-scans').textContent = stats.total_scans ?? 0;
    document.querySelector('#kpi-total-malicious').textContent = stats.total_malicious ?? 0;
    document.querySelector('#kpi-total-phishing').textContent = stats.total_phishing ?? 0;
    document.querySelector('#kpi-total-reports').textContent = stats.total_community_reports ?? 0;
    document.querySelector('#kpi-verified-threats').textContent = stats.total_verified_threats ?? 0;
    document.querySelector('#kpi-threats-24h').textContent = stats.threats_last_24h ?? 0;

    // Render Category Distribution
    const catContainer = document.querySelector('#category-bars-container');
    catContainer.replaceChildren();
    const categories = Object.entries(stats.category_distribution || {});
    const maxCat = Math.max(...categories.map(([, v]) => v), 1);
    for (const [cat, count] of categories) {
      const row = document.createElement('div');
      row.className = 'chart-bar-row';
      const label = document.createElement('span');
      label.className = 'chart-bar-label';
      label.textContent = titleCase(cat);
      const track = document.createElement('div');
      track.className = 'chart-bar-track';
      const fill = document.createElement('div');
      fill.style.height = '100%';
      fill.style.width = `${(count / maxCat) * 100}%`;
      fill.style.backgroundColor = '#415A77';
      fill.style.borderRadius = '99px';
      track.append(fill);
      const val = document.createElement('span');
      val.className = 'chart-bar-value';
      val.textContent = count;
      row.append(label, track, val);
      catContainer.append(row);
    }

    // Render Severity Distribution
    const sevContainer = document.querySelector('#severity-bars-container');
    sevContainer.replaceChildren();
    const severities = Object.entries(stats.severity_distribution || {});
    const maxSev = Math.max(...severities.map(([, v]) => v), 1);
    const sevColors = { malicious: '#A83232', high: '#C2410C', suspicious: '#8F6632', safe: '#778D7A', unknown: '#415A77' };
    for (const [sev, count] of severities) {
      const row = document.createElement('div');
      row.className = 'chart-bar-row';
      const label = document.createElement('span');
      label.className = 'chart-bar-label';
      label.textContent = titleCase(sev);
      const track = document.createElement('div');
      track.className = 'chart-bar-track';
      const fill = document.createElement('div');
      fill.style.height = '100%';
      fill.style.width = `${(count / maxSev) * 100}%`;
      fill.style.backgroundColor = sevColors[sev] || '#415A77';
      fill.style.borderRadius = '99px';
      track.append(fill);
      const val = document.createElement('span');
      val.className = 'chart-bar-value';
      val.textContent = count;
      row.append(label, track, val);
      sevContainer.append(row);
    }

    // Render Recent Scans
    const tbody = document.querySelector('#dashboard-recent-scans-tbody');
    tbody.replaceChildren();
    if (stats.recent_scans && stats.recent_scans.length) {
      for (const s of stats.recent_scans) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code style="font-size:11px;">${s.url}</code></td>
          <td><strong>${s.host}</strong></td>
          <td><span style="font-weight:800;color:${s.score >= 50 ? '#A83232' : '#778D7A'}">${s.score}/100</span></td>
          <td><span class="risk-badge badge-${s.risk_class}">${s.risk_class}</span></td>
          <td>${formatDate(s.checked_at)}</td>
          <td><a href="/scans/${s.id}/report" target="_blank" class="btn-sm btn-secondary">Report</a></td>
        `;
        tbody.append(tr);
      }
    } else {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#6b7280;padding:20px;">No scans recorded yet.</td></tr>';
    }
  } catch (err) {
    console.error('Failed to load dashboard stats:', err);
  }
}

// ---------------------------------------------------------------------------
// 2. Scan History & Compare Implementation
// ---------------------------------------------------------------------------
async function loadScanHistory() {
  const search = document.querySelector('#history-search-input')?.value.trim() || '';
  const severity = document.querySelector('#history-severity-select')?.value || 'all';
  const tbody = document.querySelector('#history-tbody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#6b7280;padding:20px;">Loading scan records…</td></tr>';

  try {
    const res = await fetch(`/api/v1/scans?q=${encodeURIComponent(search)}&severity=${severity}`);
    const data = await res.json();
    tbody.replaceChildren();

    if (!data.scans || !data.scans.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#6b7280;padding:24px;">No scan history matching criteria.</td></tr>';
      return;
    }

    selectedScansForCompare = [];
    const compareBtn = document.querySelector('#compare-selected-btn');
    if (compareBtn) compareBtn.disabled = true;

    for (const scan of data.scans) {
      const tr = document.createElement('tr');
      const tdCheck = document.createElement('td');
      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.value = scan.id;
      chk.addEventListener('change', () => {
        if (chk.checked) {
          if (selectedScansForCompare.length >= 2) {
            chk.checked = false;
            showToast('You can compare exactly 2 scans at a time.', 'info');
            return;
          }
          selectedScansForCompare.push(scan.id);
        } else {
          selectedScansForCompare = selectedScansForCompare.filter((id) => id !== scan.id);
        }
        if (compareBtn) compareBtn.disabled = selectedScansForCompare.length !== 2;
      });
      tdCheck.append(chk);

      const tdUrl = document.createElement('td');
      tdUrl.innerHTML = `<code style="font-size:11px;word-break:break-all;">${scan.url}</code>`;

      const tdRisk = document.createElement('td');
      tdRisk.innerHTML = `<span class="risk-badge badge-${scan.risk_class}">${scan.risk_class}</span>`;

      const tdScore = document.createElement('td');
      tdScore.innerHTML = `<strong style="color:${scan.score >= 50 ? '#A83232' : '#778D7A'};">${scan.score} / 100</strong>`;

      const tdMode = document.createElement('td');
      tdMode.textContent = scan.mode;

      const tdDate = document.createElement('td');
      tdDate.textContent = formatDate(scan.checked_at);

      const tdActions = document.createElement('td');
      const viewBtn = document.createElement('a');
      viewBtn.href = `/scans/${scan.id}/report`;
      viewBtn.target = '_blank';
      viewBtn.className = 'btn-sm btn-primary';
      viewBtn.textContent = 'Report';

      const delBtn = document.createElement('button');
      delBtn.className = 'btn-sm btn-secondary';
      delBtn.style.color = '#A83232';
      delBtn.textContent = 'Delete';
      delBtn.addEventListener('click', async () => {
        if (confirm(`Delete scan record for ${scan.url}?`)) {
          const delRes = await fetch(`/api/v1/scans/${scan.id}`, { method: 'DELETE' });
          if (delRes.ok) {
            showToast('Scan deleted.', 'info');
            loadScanHistory();
          }
        }
      });

      tdActions.style.display = 'flex';
      tdActions.style.gap = '6px';
      tdActions.append(viewBtn, delBtn);

      tr.append(tdCheck, tdUrl, tdRisk, tdScore, tdMode, tdDate, tdActions);
      tbody.append(tr);
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:#A83232;text-align:center;padding:20px;">Failed to load history: ${err.message}</td></tr>`;
  }
}

document.querySelector('#refresh-history-btn')?.addEventListener('click', loadScanHistory);
document.querySelector('#history-search-input')?.addEventListener('input', loadScanHistory);
document.querySelector('#history-severity-select')?.addEventListener('change', loadScanHistory);

document.querySelector('#compare-selected-btn')?.addEventListener('click', async () => {
  if (selectedScansForCompare.length !== 2) return;
  const [scanA, scanB] = selectedScansForCompare;
  const content = document.querySelector('#compare-content');
  content.innerHTML = 'Loading scan comparison…';
  compareDialog?.showModal();

  try {
    const res = await fetch(`/api/v1/scans/compare?scan_a=${scanA}&scan_b=${scanB}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to compare scans');

    content.innerHTML = `
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
        <div style="background:#EDE8D4; border:1px solid #D4C4A8; border-radius:10px; padding:14px;">
          <small>SCAN A (${formatDate(data.scan_a.checked_at)})</small>
          <p><code style="font-size:11px;">${data.scan_a.url}</code></p>
          <p>Score: <strong>${data.scan_a.score}/100</strong> · Verdict: <strong>${data.scan_a.verdict}</strong></p>
        </div>
        <div style="background:#EDE8D4; border:1px solid #D4C4A8; border-radius:10px; padding:14px;">
          <small>SCAN B (${formatDate(data.scan_b.checked_at)})</small>
          <p><code style="font-size:11px;">${data.scan_b.url}</code></p>
          <p>Score: <strong>${data.scan_b.score}/100</strong> · Verdict: <strong>${data.scan_b.verdict}</strong></p>
        </div>
      </div>
      <div style="padding:12px; background:var(--paper,#FAF8EE); border:1px solid rgba(212,196,168,0.6); border-radius:8px; margin-bottom:16px;">
        <strong>Score Delta:</strong>
        <span style="font-size:16px; font-weight:800; color:${data.score_diff > 0 ? '#A83232' : data.score_diff < 0 ? '#778D7A' : '#1B263B'}">
          ${data.score_diff > 0 ? '+' : ''}${data.score_diff}
        </span> (${data.score_diff > 0 ? 'Risk Increased' : data.score_diff < 0 ? 'Risk Decreased' : 'No Score Change'})
      </div>
      <h4>New Risk Signals in Scan B (${data.new_findings.length}):</h4>
      <ul>${data.new_findings.map((f) => `<li>[${f.severity}] ${f.summary || f.id}</li>`).join('') || '<li>None</li>'}</ul>
      <h4>Resolved Signals (${data.resolved_findings.length}):</h4>
      <ul>${data.resolved_findings.map((f) => `<li>[${f.severity}] ${f.summary || f.id}</li>`).join('') || '<li>None</li>'}</ul>
    `;
  } catch (err) {
    content.innerHTML = `<p style="color:#A83232;">Error comparing scans: ${err.message}</p>`;
  }
});

document.querySelector('[data-close-dialog="compare-dialog"]')?.addEventListener('click', () => {
  compareDialog?.close();
});

// ---------------------------------------------------------------------------
// 3. Certificate Transparency & DNS Search
// ---------------------------------------------------------------------------
async function runCtSearch() {
  const domain = document.querySelector('#ct-domain-input')?.value.trim();
  if (!domain) {
    showToast('Enter a valid domain name to search CT logs.', 'error');
    return;
  }
  const btn = document.querySelector('#ct-search-btn');
  btn.disabled = true;
  btn.textContent = 'Searching CT Logs…';

  try {
    const [ctRes, dnsRes] = await Promise.all([
      fetch(`/api/v1/ct/search?domain=${encodeURIComponent(domain)}`),
      fetch(`/api/v1/domain/dns?domain=${encodeURIComponent(domain)}`),
    ]);

    const ctData = await ctRes.json();
    const dnsData = await dnsRes.json();

    document.querySelector('#ct-results-panel').hidden = false;
    document.querySelector('#ct-total-certs').textContent = ctData.total_certs_logged ?? 0;
    document.querySelector('#ct-subdomains-count').textContent = ctData.subdomains_count ?? 0;
    document.querySelector('#ct-recent-30d').textContent = ctData.recent_certs_30d ?? 0;

    // Discovered Subdomains
    const subContainer = document.querySelector('#ct-subdomain-cloud');
    subContainer.replaceChildren();
    if (ctData.subdomains_discovered?.length) {
      for (const sub of ctData.subdomains_discovered) {
        const chip = document.createElement('span');
        chip.className = 'subdomain-chip';
        chip.textContent = sub;
        subContainer.append(chip);
      }
    } else {
      subContainer.innerHTML = '<span style="color:#6b7280;font-size:12px;">No separate subdomains found in CT logs.</span>';
    }

    // DNS Info
    const dnsBox = document.querySelector('#dns-resolution-info');
    dnsBox.innerHTML = `
      <p><strong>Hostname:</strong> <code>${dnsData.hostname}</code> (CNAME: <code>${dnsData.cname}</code>)</p>
      <p><strong>IPv4 Addresses:</strong> ${dnsData.ipv4?.length ? dnsData.ipv4.map((ip) => `<code>${ip}</code>`).join(', ') : 'None resolved'}</p>
      <p><strong>IPv6 Addresses:</strong> ${dnsData.ipv6?.length ? dnsData.ipv6.map((ip) => `<code>${ip}</code>`).join(', ') : 'None resolved'}</p>
    `;

    // Issuance History Table
    const tbody = document.querySelector('#ct-history-tbody');
    tbody.replaceChildren();
    if (ctData.issuance_history?.length) {
      for (const item of ctData.issuance_history) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code>${item.id || 'N/A'}</code></td>
          <td><strong>${item.common_name}</strong></td>
          <td style="max-width:260px;word-break:break-word;">${item.issuer}</td>
          <td>${formatDate(item.logged_at)}</td>
          <td>${formatDate(item.not_after)}</td>
        `;
        tbody.append(tr);
      }
    } else {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:16px;">No certificate history logged.</td></tr>';
    }

    showToast(`Certificate Transparency search complete for ${domain}.`, 'success');
  } catch (err) {
    showToast(`CT search failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Inspect CT Logs →';
  }
}

document.querySelector('#ct-search-btn')?.addEventListener('click', runCtSearch);

// ---------------------------------------------------------------------------
// 4. Collaborative Threat Intelligence Search
// ---------------------------------------------------------------------------
async function searchThreatIntel() {
  const query = document.querySelector('#intel-query-input')?.value.trim() || '';
  const category = document.querySelector('#intel-category-select')?.value || 'all';
  const tbody = document.querySelector('#intel-tbody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#6b7280;padding:20px;">Querying threat intelligence database…</td></tr>';

  try {
    const res = await fetch(`/api/v1/intel/search?q=${encodeURIComponent(query)}&category=${category}`);
    const data = await res.json();
    tbody.replaceChildren();

    if (!data.results || !data.results.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#6b7280;padding:24px;">No matching threat indicators found in local collaborative intelligence.</td></tr>';
      return;
    }

    for (const item of data.results) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code style="font-size:11px;word-break:break-all;">${item.indicator}</code></td>
        <td><span class="btn-sm btn-secondary">${item.indicator_type}</span></td>
        <td><strong>${titleCase(item.category)}</strong></td>
        <td><span class="risk-badge badge-${item.severity}">${item.severity}</span></td>
        <td><span style="font-weight:700;color:${item.status === 'verified' ? '#778D7A' : '#8F6632'}">${item.status}</span></td>
        <td><strong>${item.report_count}</strong></td>
        <td style="max-width:280px;font-size:11px;color:var(--muted,#415A77);">${item.evidence || item.source}</td>
      `;
      tbody.append(tr);
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:#A83232;text-align:center;padding:20px;">Failed to load threat intel: ${err.message}</td></tr>`;
  }
}

document.querySelector('#intel-search-btn')?.addEventListener('click', searchThreatIntel);

// ---------------------------------------------------------------------------
// 5. Authentication & User Profile Management
// ---------------------------------------------------------------------------
async function initAuth() {
  try {
    const res = await fetch('/api/v1/auth/me');
    const data = await res.json();
    currentUser = data.user;
    renderUserHeader();
  } catch {
    currentUser = null;
    renderUserHeader();
  }
}

function renderUserHeader() {
  const container = document.querySelector('#auth-user-container');
  if (!container) return;
  container.replaceChildren();

  if (currentUser) {
    const wrap = document.createElement('div');
    wrap.className = 'auth-user-pill';
    wrap.innerHTML = `<span>👤 ${currentUser.username}</span><span class="role-badge">${currentUser.role}</span>`;
    const logoutBtn = document.createElement('button');
    logoutBtn.type = 'button';
    logoutBtn.className = 'btn-sm btn-secondary';
    logoutBtn.textContent = 'Sign Out';
    logoutBtn.addEventListener('click', async () => {
      await fetch('/api/v1/auth/logout', { method: 'POST' });
      currentUser = null;
      renderUserHeader();
      showToast('Signed out.', 'info');
    });
    wrap.append(logoutBtn);
    container.append(wrap);
  } else {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'auth-trigger-btn';
    btn.textContent = 'Sign In / Register';
    btn.addEventListener('click', () => {
      authDialog?.showModal();
    });
    container.append(btn);
  }
}

document.querySelector('#auth-tab-login')?.addEventListener('click', () => {
  document.querySelector('#auth-tab-login').classList.add('active');
  document.querySelector('#auth-tab-register').classList.remove('active');
  document.querySelector('#auth-login-form').hidden = false;
  document.querySelector('#auth-register-form').hidden = true;
});

document.querySelector('#auth-tab-register')?.addEventListener('click', () => {
  document.querySelector('#auth-tab-register').classList.add('active');
  document.querySelector('#auth-tab-login').classList.remove('active');
  document.querySelector('#auth-register-form').hidden = false;
  document.querySelector('#auth-login-form').hidden = true;
});

document.querySelector('[data-close-dialog="auth-dialog"]')?.addEventListener('click', () => {
  authDialog?.close();
});

document.querySelector('#login-submit-btn')?.addEventListener('click', async () => {
  const username = document.querySelector('#login-username')?.value.trim();
  const password = document.querySelector('#login-password')?.value;
  if (!username || !password) {
    showToast('Enter your username and password.', 'error');
    return;
  }
  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Login failed');
    currentUser = data.user;
    renderUserHeader();
    authDialog?.close();
    showToast(`Signed in as ${currentUser.username}.`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
});

document.querySelector('#reg-submit-btn')?.addEventListener('click', async () => {
  const username = document.querySelector('#reg-username')?.value.trim();
  const email = document.querySelector('#reg-email')?.value.trim();
  const password = document.querySelector('#reg-password')?.value;
  if (!username || !email || !password) {
    showToast('Please fill in all fields.', 'error');
    return;
  }
  try {
    const res = await fetch('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Registration failed');
    currentUser = data.user;
    renderUserHeader();
    authDialog?.close();
    showToast(`Account created for ${currentUser.username}!`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// Run auth check on initialization
initAuth();

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// =========================================================================
// Collaborative Threat Intelligence Direct Submission
// =========================================================================
const submitIntelBtn = document.querySelector('#submit-intel-btn');
if (submitIntelBtn) {
  submitIntelBtn.addEventListener('click', async () => {
    const indicator = document.querySelector('#submit-intel-val')?.value.trim();
    const indicatorType = document.querySelector('#submit-intel-type')?.value;
    const category = document.querySelector('#submit-intel-cat')?.value;
    const severity = document.querySelector('#submit-intel-sev')?.value;
    const evidence = document.querySelector('#submit-intel-evidence')?.value.trim();

    if (!indicator) {
      showToast('Please enter an indicator (domain, URL, IP, or cert fingerprint).', 'error');
      return;
    }

    try {
      submitIntelBtn.disabled = true;
      const res = await fetch('/api/v1/intel/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator,
          indicator_type: indicatorType,
          category,
          severity,
          evidence,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to submit threat indicator.');
      showToast('Threat indicator contributed to community database!', 'success');
      document.querySelector('#submit-intel-val').value = '';
      document.querySelector('#submit-intel-evidence').value = '';
      searchThreatIntel();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      submitIntelBtn.disabled = false;
    }
  });
}

// =========================================================================
// Community Security Forum
// =========================================================================
let currentForumCat = 'all';
let currentForumQuery = '';
const newThreadDialog = document.querySelector('#new-thread-dialog');
const threadDetailDialog = document.querySelector('#forum-thread-detail-dialog');
let activeDetailThreadId = null;

async function loadForumThreads(cat = currentForumCat, q = currentForumQuery) {
  const container = document.querySelector('#forum-threads-list');
  if (!container) return;
  container.innerHTML = '<div class="forum-loading-state">Loading security discussions…</div>';

  try {
    let url = `/api/v1/forum/threads?sort_by=recent`;
    if (cat && cat !== 'all') url += `&category=${encodeURIComponent(cat)}`;
    if (q) url += `&q=${encodeURIComponent(q)}`;

    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to load forum threads.');
    const data = await res.json();
    const threads = data.threads || [];

    if (threads.length === 0) {
      container.innerHTML = `
        <div class="forum-empty-state">
          <p style="font-size:16px; font-weight:750; margin-bottom:6px;">No discussions found in this category.</p>
          <p style="color:var(--muted); font-size:13px; margin-bottom:16px;">Have you analyzed a new phishing attempt or suspicious certificate? Share it with the community.</p>
          <button class="button button-primary" type="button" id="forum-empty-create-btn">+ Start a Discussion</button>
        </div>
      `;
      document.querySelector('#forum-empty-create-btn')?.addEventListener('click', () => {
        newThreadDialog?.showModal();
      });
      return;
    }

    container.replaceChildren();
    threads.forEach((th) => {
      const card = document.createElement('article');
      card.className = 'forum-thread-card';
      card.setAttribute('role', 'button');
      card.setAttribute('tabindex', '0');

      const dateStr = th.created_at ? new Date(th.created_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : 'Recent';

      card.innerHTML = `
        <div class="thread-card-left">
          <button class="forum-upvote-btn" type="button" aria-label="Upvote thread" data-thread-id="${th.id}">
            <span aria-hidden="true">▲</span>
            <span class="upvote-num">${th.upvotes || 0}</span>
          </button>
        </div>
        <div class="thread-card-center">
          <div class="thread-card-header">
            <span class="cat-chip">${th.category || 'General'}</span>
            <span class="thread-meta-author">By ${escapeHtml(th.author_name || 'Anonymous')}</span>
            <span class="thread-meta-time">· ${dateStr}</span>
          </div>
          <h3 class="thread-card-title">${escapeHtml(th.title)}</h3>
          <p class="thread-card-excerpt">${escapeHtml((th.content || '').slice(0, 160))}${th.content && th.content.length > 160 ? '…' : ''}</p>
          <div class="thread-card-footer">
            <span class="thread-reply-count">💬 ${th.reply_count || 0} ${th.reply_count === 1 ? 'reply' : 'replies'}</span>
            <span>Click to view analysis & responses →</span>
          </div>
        </div>
      `;

      // Upvote click handler
      const upvoteBtn = card.querySelector('.forum-upvote-btn');
      upvoteBtn?.addEventListener('click', async (e) => {
        e.stopPropagation();
        await upvoteThread(th.id, upvoteBtn);
      });

      // Card open detail handler
      card.addEventListener('click', () => {
        openThreadDetail(th.id);
      });
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openThreadDetail(th.id);
        }
      });

      container.append(card);
    });
  } catch (err) {
    container.innerHTML = `<div class="forum-empty-state"><p style="color:var(--red);">Error loading discussions: ${escapeHtml(err.message)}</p></div>`;
  }
}

async function upvoteThread(threadId, btnElement) {
  try {
    const res = await fetch(`/api/v1/forum/threads/${encodeURIComponent(threadId)}/upvote`, { method: 'POST' });
    if (!res.ok) throw new Error('Upvote failed');
    const data = await res.json();
    btnElement.classList.add('upvoted');
    const numSpan = btnElement.querySelector('.upvote-num');
    if (numSpan) numSpan.textContent = data.upvotes;
    showToast('Upvoted!', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function openThreadDetail(threadId) {
  if (!threadDetailDialog) return;
  activeDetailThreadId = threadId;

  try {
    const res = await fetch(`/api/v1/forum/threads/${encodeURIComponent(threadId)}`);
    if (!res.ok) throw new Error('Failed to load discussion thread.');
    const th = await res.json();

    document.querySelector('#thread-detail-title').textContent = th.title;
    document.querySelector('#thread-detail-cat').textContent = th.category || 'General';
    document.querySelector('#thread-detail-author').textContent = `By ${th.author_name || 'Anonymous'}`;
    const dateStr = th.created_at ? new Date(th.created_at).toLocaleString() : 'Recent';
    document.querySelector('#thread-detail-time').textContent = `· ${dateStr}`;
    document.querySelector('#thread-detail-content').textContent = th.content;
    document.querySelector('#thread-detail-upvote-count').textContent = th.upvotes || 0;
    document.querySelector('#thread-detail-reply-count').textContent = (th.replies || []).length;

    // Upvote button inside detail dialog
    const detailUpvoteBtn = document.querySelector('#thread-detail-upvote-btn');
    if (detailUpvoteBtn) {
      detailUpvoteBtn.onclick = async () => {
        await upvoteThread(th.id, detailUpvoteBtn);
        const countSpan = document.querySelector('#thread-detail-upvote-count');
        if (countSpan) countSpan.textContent = (parseInt(countSpan.textContent, 10) || 0) + 1;
      };
    }

    // Render replies
    const repliesContainer = document.querySelector('#thread-replies-list');
    repliesContainer.replaceChildren();

    if (!th.replies || th.replies.length === 0) {
      repliesContainer.innerHTML = '<p style="color:var(--quiet); font-size:12px; margin:8px 0;">No responses yet. Share your findings or questions below.</p>';
    } else {
      th.replies.forEach((r) => {
        const item = document.createElement('div');
        item.className = 'thread-reply-item';
        const rDate = r.created_at ? new Date(r.created_at).toLocaleString() : '';
        item.innerHTML = `
          <div class="thread-reply-meta">
            <strong style="color:var(--ink);">${escapeHtml(r.author_name || 'Analyst')}</strong>
            <span style="color:var(--quiet); font-size:10px;">${rDate}</span>
          </div>
          <div class="thread-reply-content">${escapeHtml(r.content)}</div>
        `;
        repliesContainer.append(item);
      });
    }

    // Prefill author name if user signed in
    const replyAuthorInput = document.querySelector('#thread-reply-author-input');
    if (replyAuthorInput && currentUser) {
      replyAuthorInput.value = currentUser.username;
    }

    threadDetailDialog.showModal();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Forum category filter listeners
document.querySelectorAll('.forum-cat-pill').forEach((pill) => {
  pill.addEventListener('click', () => {
    document.querySelectorAll('.forum-cat-pill').forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');
    currentForumCat = pill.getAttribute('data-cat') || 'all';
    loadForumThreads(currentForumCat, currentForumQuery);
  });
});

const forumSearchInput = document.querySelector('#forum-search-input');
if (forumSearchInput) {
  let searchTimeout = null;
  forumSearchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      currentForumQuery = forumSearchInput.value.trim();
      loadForumThreads(currentForumCat, currentForumQuery);
    }, 250);
  });
}

document.querySelector('#btn-open-new-thread')?.addEventListener('click', () => {
  const authorInput = document.querySelector('#new-thread-author-input');
  if (authorInput && currentUser) {
    authorInput.value = currentUser.username;
  }
  newThreadDialog?.showModal();
});

document.querySelectorAll('[data-close-dialog="new-thread-dialog"]').forEach((el) => {
  el.addEventListener('click', () => newThreadDialog?.close());
});

document.querySelectorAll('[data-close-dialog="forum-thread-detail-dialog"]').forEach((el) => {
  el.addEventListener('click', () => threadDetailDialog?.close());
});

// Submit new discussion thread
document.querySelector('#new-thread-submit-btn')?.addEventListener('click', async () => {
  const title = document.querySelector('#new-thread-title-input')?.value.trim();
  const category = document.querySelector('#new-thread-category-select')?.value;
  const author = document.querySelector('#new-thread-author-input')?.value.trim();
  const content = document.querySelector('#new-thread-content-input')?.value.trim();

  if (!title || title.length < 3) {
    showToast('Please enter a clear topic title.', 'error');
    return;
  }
  if (!content || content.length < 5) {
    showToast('Please provide details or observations.', 'error');
    return;
  }

  try {
    const res = await fetch('/api/v1/forum/threads', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        category,
        author_name: author,
        content,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to create discussion thread.');
    showToast('Discussion thread created!', 'success');
    document.querySelector('#new-thread-title-input').value = '';
    document.querySelector('#new-thread-content-input').value = '';
    newThreadDialog?.close();
    loadForumThreads(currentForumCat, currentForumQuery);
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// Submit reply to thread
document.querySelector('#thread-reply-submit-btn')?.addEventListener('click', async () => {
  if (!activeDetailThreadId) return;
  const content = document.querySelector('#thread-reply-input')?.value.trim();
  const author = document.querySelector('#thread-reply-author-input')?.value.trim();

  if (!content || content.length < 2) {
    showToast('Reply cannot be empty.', 'error');
    return;
  }

  try {
    const res = await fetch(`/api/v1/forum/threads/${encodeURIComponent(activeDetailThreadId)}/replies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, author_name: author }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to post reply.');
    showToast('Reply posted.', 'success');
    document.querySelector('#thread-reply-input').value = '';
    openThreadDetail(activeDetailThreadId);
    loadForumThreads(currentForumCat, currentForumQuery);
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// =========================================================================
// Threat Network Mesh Dynamic Cursor System (Holst Palette)
// =========================================================================
function initThreatMeshCursor() {
  // Respect touch devices and reduced-motion preferences
  if (!window.matchMedia('(pointer: fine)').matches || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return;
  }

  let canvas = document.querySelector('#fluid-cursor-canvas');
  if (!canvas) {
    canvas = document.createElement('canvas');
    canvas.id = 'fluid-cursor-canvas';
    canvas.className = 'fluid-cursor-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    document.body.append(canvas);
  }

  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  let width = 0;
  let height = 0;
  let dpr = 1;

  function resizeCanvas() {
    dpr = window.devicePixelRatio || 1;
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
  }
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  // Holst Threat Intelligence Colors: Slate, Sage Green, Oxford Blue, Warm Sand
  const MESH_COLORS = [
    { r: 65, g: 90, b: 119 },   // #415A77 Muted Slate (Network Lines & Nodes)
    { r: 119, g: 141, b: 122 }, // #778D7A Earthy Sage (Verified Intelligence Nodes)
    { r: 27, g: 38, b: 59 },    // #1B263B Oxford Blue (Core Anchor Nodes)
    { r: 212, g: 196, b: 168 }  // #D4C4A8 Warm Sand (Telemetry Sparks)
  ];

  // Node & Ripple Object Pools
  const nodes = [];
  const MAX_NODES = 52;
  for (let i = 0; i < MAX_NODES; i++) {
    nodes.push({
      active: false,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
      radius: 0,
      maxRadius: 0,
      alpha: 1,
      decay: 0.02,
      color: MESH_COLORS[0],
      swirl: 0
    });
  }

  const ripples = [];
  const MAX_RIPPLES = 8;
  for (let i = 0; i < MAX_RIPPLES; i++) {
    ripples.push({
      active: false,
      x: 0,
      y: 0,
      radius: 0,
      maxRadius: 0,
      alpha: 1,
      decay: 0.03,
      color: MESH_COLORS[1]
    });
  }

  function spawnNode(x, y, vx, vy, radius, color, decay, swirl = 0) {
    const n = nodes.find((pt) => !pt.active);
    if (!n) return;
    n.active = true;
    n.x = x;
    n.y = y;
    n.vx = vx;
    n.vy = vy;
    n.radius = radius;
    n.maxRadius = radius;
    n.alpha = 1;
    n.decay = decay;
    n.color = color;
    n.swirl = swirl;
  }

  function spawnPulse(x, y, maxRadius, color) {
    const r = ripples.find((rp) => !rp.active);
    if (!r) return;
    r.active = true;
    r.x = x;
    r.y = y;
    r.radius = 4;
    r.maxRadius = maxRadius;
    r.alpha = 0.75;
    r.decay = 0.028;
    r.color = color;
  }

  // Pointer position tracking
  let mouseX = -100;
  let mouseY = -100;
  let prevMouseX = -100;
  let prevMouseY = -100;
  let isHoveringInteractive = false;
  let isRunning = false;
  let lastMoveTime = 0;

  function ensureAnimationRunning() {
    if (!isRunning) {
      isRunning = true;
      requestAnimationFrame(renderThreatMesh);
    }
  }

  document.addEventListener('mousemove', (e) => {
    lastMoveTime = performance.now();

    if (prevMouseX < 0) {
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    }

    mouseX = e.clientX;
    mouseY = e.clientY;

    const dx = mouseX - prevMouseX;
    const dy = mouseY - prevMouseY;
    const dist = Math.hypot(dx, dy);

    // Spawn network nodes along motion path
    if (dist > 6 || Math.random() < 0.35) {
      const col = MESH_COLORS[Math.random() < 0.65 ? 0 : 1]; // Slate or Sage
      const angle = Math.random() * Math.PI * 2;
      const spd = 0.4 + Math.random() * 1.5;
      const swirl = isHoveringInteractive ? (Math.random() - 0.5) * 0.12 : (Math.random() - 0.5) * 0.04;
      const radius = isHoveringInteractive ? 3.5 + Math.random() * 2 : 2.5 + Math.random() * 2;

      spawnNode(
        mouseX + (Math.random() - 0.5) * 16,
        mouseY + (Math.random() - 0.5) * 16,
        Math.cos(angle) * spd + dx * 0.08,
        Math.sin(angle) * spd + dy * 0.08,
        radius,
        col,
        0.016 + Math.random() * 0.014,
        swirl
      );
    }

    prevMouseX = mouseX;
    prevMouseY = mouseY;
    ensureAnimationRunning();
  });

  document.addEventListener('mouseleave', () => {
    mouseX = -100;
    mouseY = -100;
    prevMouseX = -100;
    prevMouseY = -100;
  });

  // MOUSE CLICK: Neural Data Pulse & Radial Node Burst
  document.addEventListener('mousedown', (e) => {
    const cx = e.clientX;
    const cy = e.clientY;

    // Concentric encrypted data shockwaves
    spawnPulse(cx, cy, 65, MESH_COLORS[1]); // Sage pulse
    spawnPulse(cx, cy, 105, MESH_COLORS[0]); // Slate pulse

    // High-speed data packet sparks scattering into the mesh
    for (let i = 0; i < 20; i++) {
      const angle = (i / 20) * Math.PI * 2 + (Math.random() - 0.5) * 0.3;
      const spd = 3 + Math.random() * 7.5;
      const col = MESH_COLORS[Math.floor(Math.random() * MESH_COLORS.length)];
      spawnNode(cx, cy, Math.cos(angle) * spd, Math.sin(angle) * spd, 3 + Math.random() * 2.5, col, 0.02 + Math.random() * 0.018);
    }

    ensureAnimationRunning();
  });

  // Interactive Hover Watcher (Perimeter orbit & brighter graph lines)
  const interactiveSelectors = 'a, button, input, textarea, select, [role="button"], .tab-btn, .example-chip, .cat-chip, .forum-cat-pill, .forum-thread-card';
  document.addEventListener('mouseover', (e) => {
    if (e.target.closest(interactiveSelectors)) isHoveringInteractive = true;
  });
  document.addEventListener('mouseout', (e) => {
    if (e.target.closest(interactiveSelectors)) isHoveringInteractive = false;
  });

  // 60fps Threat Mesh Render Loop
  function renderThreatMesh() {
    ctx.clearRect(0, 0, width, height);

    let activeCount = 0;

    // 1. Render Expanding Data Pulse Ripples
    for (let i = 0; i < MAX_RIPPLES; i++) {
      const r = ripples[i];
      if (!r.active) continue;
      activeCount++;

      r.radius += (r.maxRadius - r.radius) * 0.12 + 1.2;
      r.alpha -= r.decay;

      if (r.alpha <= 0.01 || r.radius >= r.maxRadius) {
        r.active = false;
        continue;
      }

      ctx.beginPath();
      ctx.arc(r.x, r.y, r.radius, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${r.color.r}, ${r.color.g}, ${r.color.b}, ${Math.max(0, r.alpha * 0.85)})`;
      ctx.lineWidth = Math.max(0.7, 2.4 * (r.alpha / 0.75));
      ctx.stroke();
    }

    // 2. Draw Dynamic Connective Mesh Topology Lines between Nodes
    const activeNodes = nodes.filter((n) => n.active);
    const lineThreshold = isHoveringInteractive ? 82 : 72;

    for (let i = 0; i < activeNodes.length; i++) {
      const n1 = activeNodes[i];
      for (let j = i + 1; j < activeNodes.length; j++) {
        const n2 = activeNodes[j];
        const dist = Math.hypot(n2.x - n1.x, n2.y - n1.y);

        if (dist < lineThreshold) {
          const lineAlpha = (1 - dist / lineThreshold) * Math.min(n1.alpha, n2.alpha) * (isHoveringInteractive ? 0.75 : 0.55);
          ctx.beginPath();
          ctx.moveTo(n1.x, n1.y);
          ctx.lineTo(n2.x, n2.y);
          ctx.strokeStyle = `rgba(${n1.color.r}, ${n1.color.g}, ${n1.color.b}, ${lineAlpha})`;
          ctx.lineWidth = isHoveringInteractive ? 1.2 : 0.9;
          ctx.stroke();
        }
      }
    }

    // Connect nearest nodes to current pointer tip
    if (mouseX > 0 && mouseY > 0) {
      for (let i = 0; i < activeNodes.length; i++) {
        const n = activeNodes[i];
        const distToPointer = Math.hypot(mouseX - n.x, mouseY - n.y);
        if (distToPointer < 68) {
          const tipAlpha = (1 - distToPointer / 68) * n.alpha * 0.6;
          ctx.beginPath();
          ctx.moveTo(mouseX, mouseY);
          ctx.lineTo(n.x, n.y);
          ctx.strokeStyle = `rgba(65, 90, 119, ${tipAlpha})`;
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      }
    }

    // 3. Update & Render Active Threat Intelligence Nodes
    for (let i = 0; i < MAX_NODES; i++) {
      const n = nodes[i];
      if (!n.active) continue;
      activeCount++;

      // Viscous damping
      n.x += n.vx;
      n.y += n.vy;
      n.vx *= 0.94;
      n.vy *= 0.94;

      // Swirling vorticity
      if (n.swirl !== 0) {
        n.x += -n.vy * n.swirl;
        n.y += n.vx * n.swirl;
      }

      n.alpha -= n.decay;
      n.radius = n.maxRadius * (n.alpha > 0 ? Math.pow(n.alpha, 0.65) : 0);

      if (n.alpha <= 0.01 || n.radius <= 0.5) {
        n.active = false;
        continue;
      }

      // Render glowing node bead
      const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, Math.max(1, n.radius));
      grad.addColorStop(0, `rgba(${n.color.r}, ${n.color.g}, ${n.color.b}, ${n.alpha * 0.95})`);
      grad.addColorStop(0.6, `rgba(${n.color.r}, ${n.color.g}, ${n.color.b}, ${n.alpha * 0.45})`);
      grad.addColorStop(1, `rgba(${n.color.r}, ${n.color.g}, ${n.color.b}, 0)`);

      ctx.beginPath();
      ctx.arc(n.x, n.y, Math.max(0.5, n.radius), 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();
    }

    // 4. Central Precision Tip Pointer
    if (mouseX > 0 && mouseY > 0) {
      const pointerRadius = isHoveringInteractive ? 5 : 3.5;

      // Precision core dot in Oxford Blue (#1B263B)
      ctx.beginPath();
      ctx.arc(mouseX, mouseY, pointerRadius, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(27, 38, 59, 0.95)';
      ctx.fill();

      // Soft Sage/Slate outer radar aura
      ctx.beginPath();
      ctx.arc(mouseX, mouseY, pointerRadius + 3.5, 0, Math.PI * 2);
      ctx.strokeStyle = isHoveringInteractive ? 'rgba(119, 141, 122, 0.75)' : 'rgba(65, 90, 119, 0.4)';
      ctx.lineWidth = 1.3;
      ctx.stroke();
    }

    // 5. Throttling for 0% Idle CPU
    if (activeCount === 0 && performance.now() - lastMoveTime > 120) {
      isRunning = false;
      return;
    }

    requestAnimationFrame(renderThreatMesh);
  }

  ensureAnimationRunning();
}

initThreatMeshCursor();

/* =====================================================================
   MINIMAL TRUST CARD BOOT / LOADING ANIMATION
   ===================================================================== */
function initBootSequence() {
  const overlay = document.querySelector('#system-boot-overlay');
  if (!overlay) return;

  const progressBar = document.querySelector('#boot-progress-bar');
  const rebootBtn = document.querySelector('#reboot-system-btn');
  const brandEmblem = document.querySelector('.brand-mark');

  let isBooting = false;
  let timerId = null;

  function dismissBoot() {
    if (!isBooting) return;
    isBooting = false;
    clearTimeout(timerId);

    if (progressBar) progressBar.style.width = '100%';
    overlay.classList.add('boot-completed');
    sessionStorage.setItem('tc_boot_completed', 'true');
    document.body.style.overflow = '';

    setTimeout(() => {
      overlay.hidden = true;
      input?.focus();
    }, 500);
  }

  function startBoot(force = false) {
    const hasSeenBoot = sessionStorage.getItem('tc_boot_completed') === 'true';
    const urlParams = new URLSearchParams(window.location.search);
    const forceParam = urlParams.has('boot') || window.location.hash === '#boot';

    if (!force && hasSeenBoot && !forceParam) {
      overlay.hidden = true;
      overlay.classList.add('boot-completed');
      return;
    }

    isBooting = true;
    clearTimeout(timerId);

    overlay.hidden = false;
    overlay.classList.remove('boot-completed');
    document.body.style.overflow = 'hidden';

    if (progressBar) {
      progressBar.style.width = '0%';
      requestAnimationFrame(() => {
        setTimeout(() => {
          if (progressBar && isBooting) progressBar.style.width = '45%';
        }, 350);
        setTimeout(() => {
          if (progressBar && isBooting) progressBar.style.width = '78%';
        }, 1200);
        setTimeout(() => {
          if (progressBar && isBooting) progressBar.style.width = '100%';
        }, 2100);
      });
    }

    // Smoothly complete after one full cycle (~2.5s)
    timerId = setTimeout(dismissBoot, 2500);
  }

  // Any click or keypress dismisses immediately
  overlay.addEventListener('click', dismissBoot);
  window.addEventListener('keydown', (e) => {
    if (isBooting && (e.key === 'Escape' || e.key === ' ' || e.key === 'Enter')) {
      e.preventDefault();
      dismissBoot();
    }
  });

  rebootBtn?.addEventListener('click', () => startBoot(true));
  brandEmblem?.addEventListener('click', (e) => {
    if (e.altKey) {
      e.preventDefault();
      startBoot(true);
    }
  });

  startBoot(false);
}

initBootSequence();


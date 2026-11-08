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
  icon.textContent = type === 'success' ? '✓' : type === 'error' ? '⚠' : '🍉';
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
    btn.classList.toggle('active', btn.getAttribute('data-view') === viewId);
  });
  document.querySelectorAll('.top-nav a').forEach((link) => {
    const target = link.getAttribute('data-tab-target');
    if (target) link.classList.toggle('nav-active', target === viewId);
  });

  if (viewId === 'view-dashboard') loadDashboardStats();
  if (viewId === 'view-history') loadScanHistory();
  if (viewId === 'view-intel') searchThreatIntel();
  if (viewId === 'view-forum') loadForumThreads();
}

document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const view = btn.getAttribute('data-view');
    if (view) switchView(view);
  });
});

document.querySelectorAll('.top-nav a[data-tab-target]').forEach((link) => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const target = link.getAttribute('data-tab-target');
    if (target) switchView(target);
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

function renderResult(data) {
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
  card.className = `result-card trust-card ${verdictClass}`;

  const header = document.createElement('div');
  header.className = 'result-header';
  const verdict = document.createElement('div');
  verdict.className = 'verdict-group';
  const icon = document.createElement('span');
  icon.className = 'verdict-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = data.verdict === 'known_threat' || data.verdict === 'suspicious' ? '!' : data.verdict === 'caution' ? '⚠' : data.verdict === 'no_strong_warning' ? '✓' : '?';
  const verdictText = document.createElement('div');
  const kicker = document.createElement('p');
  kicker.className = 'step-label';
  kicker.textContent = 'TRUST CARD RESULT';
  const title = document.createElement('h2');
  title.className = 'result-title';
  title.textContent = verdictTitle(data.verdict);
  const summary = document.createElement('p');
  summary.className = 'result-summary';
  summary.textContent = verdictSummary(data.verdict);
  verdictText.append(kicker, title, summary);
  verdict.append(icon, verdictText);
  const checked = document.createElement('span');
  checked.className = 'checked-at';
  checked.textContent = `Checked ${formatDate(data.checked_at)}`;
  header.append(verdict, checked);
  card.append(header);

  // Target Sector Pill
  if (data.target_category) {
    const sectorPill = document.createElement('span');
    sectorPill.className = 'target-sector-pill';
    sectorPill.style.margin = '14px 24px 0';
    sectorPill.textContent = `Target Category: ${data.target_category}`;
    card.append(sectorPill);
  }

  // 5-Tier Risk Classification Banner
  if (data.risk_classification) {
    const banner = document.createElement('div');
    banner.className = 'risk-classification-banner';
    banner.style.margin = '12px 24px 0';
    const badge = document.createElement('span');
    badge.className = `risk-badge badge-${data.risk_classification.key}`;
    badge.textContent = data.risk_classification.label;
    const desc = document.createElement('span');
    desc.style.fontSize = '12px';
    desc.style.color = '#4b5563';
    desc.textContent = data.risk_classification.description;
    banner.append(badge, desc);
    card.append(banner);
  }

  // Certificate problem banner
  const hasCertProblem = data.verdict === 'caution' || findings.some((f) => (f.group === 'certificate' || f.category === 'certificate') && (f.severity === 'medium' || f.severity === 'high'));
  if (hasCertProblem) {
    const certBanner = document.createElement('div');
    certBanner.className = 'certificate-banner';
    certBanner.setAttribute('role', 'alert');
    const bannerIcon = document.createElement('span');
    bannerIcon.className = 'banner-icon';
    bannerIcon.textContent = '⚠';
    bannerIcon.setAttribute('aria-hidden', 'true');
    const bannerText = document.createElement('div');
    const bannerHeading = document.createElement('strong');
    bannerHeading.textContent = 'Certificate problem detected';
    const bannerMsg = document.createElement('p');
    bannerMsg.textContent = 'This site has a certificate validation or cryptographic trust failure. Never enter credentials or sensitive details on a site with certificate problems.';
    bannerText.append(bannerHeading, bannerMsg);
    certBanner.append(bannerIcon, bannerText);
    card.append(certBanner);
  }

  const site = document.createElement('div');
  site.className = 'result-site';
  const siteIcon = document.createElement('span');
  siteIcon.className = 'site-icon';
  siteIcon.setAttribute('aria-hidden', 'true');
  siteIcon.textContent = '↗';
  const siteText = document.createElement('div');
  const siteLabel = document.createElement('span');
  siteLabel.className = 'site-label';
  siteLabel.textContent = 'LINK CHECKED';
  const siteUrl = document.createElement('code');
  siteUrl.textContent = selectedUrl;
  siteText.append(siteLabel, siteUrl);
  site.append(siteIcon, siteText);
  card.append(site);

  const metrics = document.createElement('div');
  metrics.className = 'result-metrics';
  const freshest = freshestFeed(data.feed_status || []);
  metrics.append(
    makeMetric('Confidence', confidenceLabel(data.confidence), 'Evidence strength'),
    makeMetric('Coverage', coverageShortLabel(data.coverage), coverageDetail(data)),
    makeMetric('Threat data', data.feed_stale ? 'Stale or missing' : 'Current', freshest ? `Latest snapshot: ${formatDate(freshest)}` : 'No feed snapshots available'),
  );
  if (data.scoring) {
    metrics.append(
      makeMetric('Risk indicators', `${data.scoring.score}/100`, `${data.scoring.checked_count} of 7 checks run`),
    );
  }
  card.append(metrics);

  const coverage = document.createElement('p');
  coverage.className = 'coverage-note';
  coverage.textContent = coverageExplanation(data);
  card.append(coverage);

  // AI Security Explanation Panel
  if (data.ai_explanation) {
    const aiPanel = document.createElement('section');
    aiPanel.className = 'ai-panel';
    const aiHeader = document.createElement('div');
    aiHeader.className = 'ai-header';
    const aiTitle = document.createElement('div');
    aiTitle.className = 'ai-title';
    aiTitle.innerHTML = '<span>🤖</span> AI Security Explanation & Threat Synthesis';
    const aiBadge = document.createElement('span');
    aiBadge.className = 'ai-badge';
    aiBadge.textContent = data.ai_explanation.source || 'Intelligence Synthesis';
    aiHeader.append(aiTitle, aiBadge);
    aiPanel.append(aiHeader);

    const summaryP = document.createElement('p');
    summaryP.className = 'ai-summary';
    summaryP.textContent = data.ai_explanation.summary;
    aiPanel.append(summaryP);

    if (data.ai_explanation.attack_techniques?.length) {
      const sub = document.createElement('div');
      sub.className = 'ai-section-subtitle';
      sub.textContent = 'Potential Attack Vectors';
      const tagList = document.createElement('div');
      tagList.className = 'ai-tag-list';
      for (const t of data.ai_explanation.attack_techniques) {
        const tag = document.createElement('span');
        tag.className = 'ai-tag';
        tag.textContent = t;
        tagList.append(tag);
      }
      aiPanel.append(sub, tagList);
    }
    card.append(aiPanel);
  }

  // Security Pillars Assessment
  if (data.scoring && data.scoring.pillars) {
    const pillarsPanel = document.createElement('section');
    pillarsPanel.className = 'pillars-panel';
    pillarsPanel.setAttribute('aria-labelledby', 'pillars-heading');

    const pillarsHeader = document.createElement('div');
    pillarsHeader.className = 'pillars-header';
    const pillarsTitle = document.createElement('h3');
    pillarsTitle.id = 'pillars-heading';
    pillarsTitle.className = 'pillars-title';
    pillarsTitle.textContent = 'Security Pillars Assessment';
    const pillarsSummary = document.createElement('span');
    pillarsSummary.className = 'pillars-summary-pill';
    pillarsSummary.textContent = data.scoring.summary;
    pillarsHeader.append(pillarsTitle, pillarsSummary);
    pillarsPanel.append(pillarsHeader);

    const pillarList = document.createElement('div');
    pillarList.className = 'pillar-list';

    for (const [, pillar] of Object.entries(data.scoring.pillars)) {
      const row = document.createElement('div');
      row.className = 'pillar-row';

      const badge = document.createElement('span');
      badge.className = 'pillar-badge';
      badge.dataset.status = pillar.status;
      badge.textContent = pillar.status === 'not_checked' ? 'Not checked' : pillar.status;

      const content = document.createElement('div');
      content.className = 'pillar-content';

      const nameLine = document.createElement('div');
      nameLine.className = 'pillar-name-line';
      const name = document.createElement('strong');
      name.className = 'pillar-name';
      name.textContent = pillar.name;
      nameLine.append(name);
      if (pillar.status !== 'not_checked') {
        const scoreSpan = document.createElement('span');
        scoreSpan.className = 'pillar-score';
        scoreSpan.textContent = `(Risk: ${pillar.score}/100)`;
        nameLine.append(scoreSpan);
      }

      const why = document.createElement('p');
      why.className = 'pillar-why';
      why.textContent = pillar.why;

      content.append(nameLine, why);

      if (Array.isArray(pillar.findings) && pillar.findings.length > 0) {
        const fToggle = document.createElement('details');
        fToggle.className = 'pillar-findings-toggle';
        const fSummary = document.createElement('summary');
        fSummary.textContent = `${pillar.findings.length} signal${pillar.findings.length === 1 ? '' : 's'} observed`;
        const fList = document.createElement('ul');
        fList.className = 'pillar-findings-list';
        for (const f of pillar.findings) {
          const item = document.createElement('li');
          item.textContent = f.summary || f.explanation || f.id;
          fList.append(item);
        }
        fToggle.append(fSummary, fList);
        content.append(fToggle);
      }

      row.append(badge, content);
      pillarList.append(row);
    }

    pillarsPanel.append(pillarList);
    card.append(pillarsPanel);
  }

  const details = document.createElement('div');
  details.className = 'result-detail-grid';
  const evidence = document.createElement('section');
  evidence.className = 'detail-panel evidence-panel';
  evidence.setAttribute('aria-labelledby', 'evidence-title');
  const evidenceHead = document.createElement('div');
  evidenceHead.className = 'detail-heading';
  const evidenceTitle = document.createElement('h3');
  evidenceTitle.id = 'evidence-title';
  evidenceTitle.textContent = 'Why this result';
  const findingCount = document.createElement('span');
  findingCount.className = 'detail-count';
  findingCount.textContent = `${findings.length} ${findings.length === 1 ? 'signal' : 'signals'}`;
  evidenceHead.append(evidenceTitle, findingCount);
  evidence.append(evidenceHead);

  if (findings.length) {
    const list = document.createElement('div');
    list.className = 'finding-list';
    for (const finding of findings) list.append(makeFinding(finding));
    evidence.append(list);
  } else {
    const empty = document.createElement('p');
    empty.className = 'empty-finding';
    empty.textContent = 'No known threat match or strong warning appeared in these checks.';
    evidence.append(empty);
  }

  if (Array.isArray(data.redirect_hosts) && data.redirect_hosts.length) {
    const redirects = document.createElement('div');
    redirects.className = 'redirect-detail';
    const label = document.createElement('strong');
    label.textContent = 'Redirect sites reached';
    const hosts = document.createElement('p');
    hosts.textContent = data.redirect_hosts.join(' → ');
    redirects.append(label, hosts);
    evidence.append(redirects);
  }

  const next = document.createElement('section');
  next.className = 'detail-panel next-panel';
  next.setAttribute('aria-labelledby', 'next-title');
  const nextTitle = document.createElement('h3');
  nextTitle.id = 'next-title';
  nextTitle.textContent = 'A safer next step';
  const list = document.createElement('ul');
  for (const text of data.next_steps || []) {
    const item = document.createElement('li');
    item.textContent = text;
    list.append(item);
  }
  next.append(nextTitle, list);
  details.append(evidence, next);
  card.append(details);

  if (data.certificate) {
    const certBlock = document.createElement('details');
    certBlock.className = 'cert-details-block';
    const certSummary = document.createElement('summary');
    certSummary.className = 'cert-details-summary';
    certSummary.textContent = 'Certificate details';
    const certGrid = document.createElement('div');
    certGrid.className = 'cert-grid';

    const fields = [
      ['Subject', data.certificate.subject],
      ['Issuer', data.certificate.issuer],
      ['SANs', Array.isArray(data.certificate.sans) && data.certificate.sans.length ? data.certificate.sans.join(', ') : 'None'],
      ['Valid from', formatDate(data.certificate.valid_from)],
      ['Valid to', formatDate(data.certificate.valid_to)],
      ['Key', `${data.certificate.key_type || 'Unknown'} (${data.certificate.key_size || 0} bits)`],
      ['Signature algorithm', data.certificate.signature_algorithm || 'Unknown'],
      ['SCT count', `${data.certificate.sct_count || 0} embedded timestamp(s)`],
    ];
    for (const [label, val] of fields) {
      const row = document.createElement('div');
      row.className = 'cert-field';
      const k = document.createElement('span');
      k.className = 'cert-field-name';
      k.textContent = label;
      const v = document.createElement('span');
      v.className = 'cert-field-val';
      v.textContent = val || 'None';
      row.append(k, v);
      certGrid.append(row);
    }
    certBlock.append(certSummary, certGrid);
    card.append(certBlock);
  }

  if (resultNotice) {
    const notice = document.createElement('p');
    notice.className = 'notice';
    notice.setAttribute('role', 'status');
    notice.textContent = resultNotice;
    card.append(notice);
  }

  const actions = document.createElement('div');
  actions.className = 'result-actions';

  // Printable Report Button
  if (data.scan_id) {
    const reportBtn = makeButton('🖨️ Download PDF Report', 'button button-secondary', () => {
      window.open(`/scans/${data.scan_id}/report`, '_blank');
    });
    actions.append(reportBtn);
  }

  if (data.coverage === 'local_only' || (data.scan_error && data.scan_error !== 'scanner_unavailable')) {
    actions.append(makeButton('Run optional live check', 'button button-primary', () => {
      document.querySelector('#consent-host').textContent = selectedUrl;
      const cb = document.querySelector('#consent-ct-rdap');
      if (cb) cb.checked = false;
      scanDialog?.showModal();
    }));
  }
  if (data.verdict !== 'known_threat') {
    const category = document.createElement('select');
    category.className = 'report-select';
    category.setAttribute('aria-label', 'Choose a report category');
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Choose a category';
    placeholder.disabled = true;
    placeholder.selected = true;
    category.append(placeholder);
    for (const [value, label] of [
      ['phishing', 'Phishing'],
      ['malware', 'Malware'],
      ['fake_banking', 'Fake Banking Portal'],
      ['fraudulent_payment', 'Fraudulent Payment'],
      ['fake_recruitment', 'Fake Recruitment Portal'],
      ['impersonation', 'Impersonation'],
      ['other', 'Other'],
    ]) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      category.append(option);
    }
    const reportButton = makeButton('Report this link', 'button button-secondary', () => {
      if (category.value) submitReport(category.value);
    });
    reportButton.disabled = true;
    category.addEventListener('change', () => {
      reportButton.disabled = !category.value;
    });
    actions.append(category, reportButton);
  }
  card.append(actions);
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
      fill.style.backgroundColor = '#ff385c';
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
    const sevColors = { malicious: '#dc2626', high: '#e11d48', suspicious: '#d97706', safe: '#059669', unknown: '#6b7280' };
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
      fill.style.backgroundColor = sevColors[sev] || '#4b5563';
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
          <td><span style="font-weight:800;color:${s.score >= 50 ? '#e11d48' : '#059669'}">${s.score}/100</span></td>
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
      tdScore.innerHTML = `<strong style="color:${scan.score >= 50 ? '#e11d48' : '#059669'};">${scan.score} / 100</strong>`;

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
      delBtn.style.color = '#dc2626';
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
    tbody.innerHTML = `<tr><td colspan="7" style="color:#dc2626;text-align:center;padding:20px;">Failed to load history: ${err.message}</td></tr>`;
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
        <div style="background:#fff5f7; border:1px solid #ffd0d8; border-radius:10px; padding:14px;">
          <small>SCAN A (${formatDate(data.scan_a.checked_at)})</small>
          <p><code style="font-size:11px;">${data.scan_a.url}</code></p>
          <p>Score: <strong>${data.scan_a.score}/100</strong> · Verdict: <strong>${data.scan_a.verdict}</strong></p>
        </div>
        <div style="background:#fff5f7; border:1px solid #ffd0d8; border-radius:10px; padding:14px;">
          <small>SCAN B (${formatDate(data.scan_b.checked_at)})</small>
          <p><code style="font-size:11px;">${data.scan_b.url}</code></p>
          <p>Score: <strong>${data.scan_b.score}/100</strong> · Verdict: <strong>${data.scan_b.verdict}</strong></p>
        </div>
      </div>
      <div style="padding:12px; background:#fff; border:1px solid #d1d5db; border-radius:8px; margin-bottom:16px;">
        <strong>Score Delta:</strong>
        <span style="font-size:16px; font-weight:800; color:${data.score_diff > 0 ? '#e11d48' : data.score_diff < 0 ? '#059669' : '#374151'}">
          ${data.score_diff > 0 ? '+' : ''}${data.score_diff}
        </span> (${data.score_diff > 0 ? 'Risk Increased' : data.score_diff < 0 ? 'Risk Decreased' : 'No Score Change'})
      </div>
      <h4>New Risk Signals in Scan B (${data.new_findings.length}):</h4>
      <ul>${data.new_findings.map((f) => `<li>[${f.severity}] ${f.summary || f.id}</li>`).join('') || '<li>None</li>'}</ul>
      <h4>Resolved Signals (${data.resolved_findings.length}):</h4>
      <ul>${data.resolved_findings.map((f) => `<li>[${f.severity}] ${f.summary || f.id}</li>`).join('') || '<li>None</li>'}</ul>
    `;
  } catch (err) {
    content.innerHTML = `<p style="color:#dc2626;">Error comparing scans: ${err.message}</p>`;
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
        <td><span style="font-weight:700;color:${item.status === 'verified' ? '#059669' : '#b45309'}">${item.status}</span></td>
        <td><strong>${item.report_count}</strong></td>
        <td style="max-width:280px;font-size:11px;color:#4b5563;">${item.evidence || item.source}</td>
      `;
      tbody.append(tr);
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:#dc2626;text-align:center;padding:20px;">Failed to load threat intel: ${err.message}</td></tr>`;
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
// Dynamic Cyber Mouse Cursor Implementation
// =========================================================================
function initDynamicCursor() {
  const dot = document.querySelector('#cursor-dot');
  const ring = document.querySelector('#cursor-ring');
  if (!dot || !ring) return;

  // Respect touch devices and reduced-motion preference
  if (!window.matchMedia('(pointer: fine)').matches || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return;
  }

  let mouseX = window.innerWidth / 2;
  let mouseY = window.innerHeight / 2;
  let ringX = mouseX;
  let ringY = mouseY;
  let isVisible = false;

  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
    dot.style.transform = `translate3d(${mouseX}px, ${mouseY}px, 0) translate(-50%, -50%)`;
    if (!isVisible) {
      dot.style.opacity = '1';
      ring.style.opacity = '1';
      isVisible = true;
    }
  });

  document.addEventListener('mouseleave', () => {
    dot.style.opacity = '0';
    ring.style.opacity = '0';
    isVisible = false;
  });

  document.addEventListener('mouseenter', () => {
    dot.style.opacity = '1';
    ring.style.opacity = '1';
    isVisible = true;
  });

  document.addEventListener('mousedown', () => {
    ring.classList.add('cursor-click');
  });

  document.addEventListener('mouseup', () => {
    ring.classList.remove('cursor-click');
  });

  const interactiveSelectors = 'a, button, input, textarea, select, [role="button"], .tab-btn, .example-chip, .cat-chip, .forum-cat-pill, .forum-thread-card';
  document.addEventListener('mouseover', (e) => {
    if (e.target.closest(interactiveSelectors)) {
      ring.classList.add('cursor-hover');
    }
  });
  document.addEventListener('mouseout', (e) => {
    if (e.target.closest(interactiveSelectors)) {
      ring.classList.remove('cursor-hover');
    }
  });

  function renderCursor() {
    ringX += (mouseX - ringX) * 0.18;
    ringY += (mouseY - ringY) * 0.18;
    ring.style.transform = `translate3d(${ringX}px, ${ringY}px, 0) translate(-50%, -50%)`;
    requestAnimationFrame(renderCursor);
  }
  requestAnimationFrame(renderCursor);
}

initDynamicCursor();

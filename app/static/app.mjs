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

input.addEventListener('input', updateInputPreview);
findButton.addEventListener('click', findLinks);
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

document.querySelector('#clear-input').addEventListener('click', () => {
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
});

document.querySelector('#try-sample').addEventListener('click', () => {
  input.value = 'URGENT: Verify your account now to avoid suspension. Send your OTP and pay the ₹99 verification fee: https://secure-account-check.example/verify';
  updateInputPreview();
  input.focus();
});

for (const chip of document.querySelectorAll('.example-chip')) {
  chip.addEventListener('click', () => {
    const url = chip.getAttribute('data-example-url');
    if (url) {
      input.value = url;
      updateInputPreview();
      input.focus();
    }
  });
}

document.querySelector('#approve-scan').addEventListener('click', async () => {
  const ctRdapConsent = Boolean(document.querySelector('#consent-ct-rdap')?.checked);
  scanDialog.close();
  await analyze('full_scan', true, ctRdapConsent);
});
document.querySelector('#decline-scan').addEventListener('click', declineLiveScan);
document.querySelector('[data-close-dialog="scan-consent"]').addEventListener('click', declineLiveScan);
scanDialog.addEventListener('cancel', (event) => {
  event.preventDefault();
  declineLiveScan();
});

document.querySelector('#refresh-feeds').addEventListener('click', () => feedDialog.showModal());
document.querySelector('#cancel-feeds').addEventListener('click', () => feedDialog.close());
document.querySelector('[data-close-dialog="feed-consent"]').addEventListener('click', () => feedDialog.close());
document.querySelector('#approve-feeds').addEventListener('click', refreshFeeds);

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
  scanDialog.close();
  resultNotice = 'Live scan not run. Your local-only result is still available.';
  if (currentResult) renderResult(currentResult);
}

async function analyze(mode, consent, ctRdapConsent = false) {
  input.disabled = true;
  findButton.disabled = true;
  clearButton.disabled = true;
  sampleButton.disabled = true;
  if (localButton) localButton.disabled = true;
  resultRegion.hidden = false;
  resultRegion.replaceChildren(makeStatus('Checking this link…'));
  resultNotice = '';
  try {
    const response = await fetch('/api/v1/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildAnalyzeRequest(selectedUrl, mode, consent, selectedFlags, ctRdapConsent)),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(apiError(data, 'The link could not be checked.'));
    currentResult = data;
    renderResult(data);
    resultRegion.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    resultRegion.replaceChildren(makeStatus(error.message || 'The check could not be completed.'));
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
    bannerMsg.textContent = 'This site has a certificate validation or trust failure. Never enter credentials or sensitive details on a site with certificate problems.';
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
  card.append(metrics);

  const coverage = document.createElement('p');
  coverage.className = 'coverage-note';
  coverage.textContent = coverageExplanation(data);
  card.append(coverage);

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
  if (data.coverage === 'local_only' || (data.scan_error && data.scan_error !== 'scanner_unavailable')) {
    actions.append(makeButton('Run optional live check', 'button button-primary', () => {
      document.querySelector('#consent-host').textContent = selectedUrl;
      const cb = document.querySelector('#consent-ct-rdap');
      if (cb) cb.checked = false;
      scanDialog.showModal();
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
    for (const [value, label] of [['phishing', 'Phishing'], ['malware', 'Malware'], ['impersonation', 'Impersonation'], ['other', 'Other']]) {
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
  } catch (error) {
    resultNotice = error.message;
    renderResult(currentResult);
  }
}

async function refreshFeeds() {
  const button = document.querySelector('#approve-feeds');
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
    feedDialog.close();
    updateFeedStatus(data);
    const updated = data.results.filter((item) => item.updated).length;
    resultNotice = updated ? `${updated} threat feed${updated === 1 ? '' : 's'} refreshed.` : 'Feeds could not be refreshed. Previous saved data remains available.';
    if (currentResult) renderResult(currentResult);
  } catch (error) {
    feedDialog.close();
    document.querySelector('#feed-summary').textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = 'Refresh feeds';
  }
}

function updateFeedStatus(data) {
  const status = document.querySelector('#feed-status');
  status.replaceChildren();
  for (const item of data.providers || []) {
    const chip = document.createElement('span');
    chip.className = 'feed-chip';
    const state = !item.available ? 'not loaded' : item.stale ? 'stale' : `updated ${formatDate(item.updated_at)}`;
    const label = item.source === 'Demo seed' ? 'Demo data, not real threat intelligence' : item.source;
    chip.textContent = `${label} · ${state}`;
    status.append(chip);
  }
  document.querySelector('#feed-summary').textContent = data.stale
    ? 'One or more feeds are missing or stale. A no-match is not a clean bill of health.'
    : 'Threat feeds are up to date.';
}

function renderCuePills(container, flags, emptyMessage) {
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

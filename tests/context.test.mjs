import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

let context;
try {
  context = await import('../app/static/context.mjs');
} catch {
  context = null;
}

test('extracts at most five unique HTTP and HTTPS links and removes trailing punctuation', () => {
  assert.equal(typeof context?.extractUrls, 'function', 'context module must export extractUrls');
  assert.deepEqual(
    context.extractUrls('See https://one.example/path?x=1, then https://one.example/path?x=1. Also http://two.example/x). ftp://three.example/file'),
    ['https://one.example/path?x=1', 'http://two.example/x'],
  );
});

test('caps extracted links at five', () => {
  assert.deepEqual(
    context?.extractUrls?.('https://a.example https://b.example https://c.example https://d.example https://e.example https://f.example'),
    ['https://a.example/', 'https://b.example/', 'https://c.example/', 'https://d.example/', 'https://e.example/'],
  );
});

test('normalizes hosts and removes fragments before deduplicating links', () => {
  assert.deepEqual(
    context?.extractUrls?.('HTTPS://BÜCHER.example.:443/path?token=a#first https://xn--bcher-kva.example/path?token=a#second'),
    ['https://xn--bcher-kva.example/path?token=a'],
  );
});

test('skips malformed and credential-bearing links while retaining IPv6 URLs', () => {
  assert.deepEqual(
    context?.extractUrls?.('https://%zz.example/path https://user:secret@example.com/login http://[::1]'),
    ['http://[::1]/'],
  );
});

test('multiple links require a selected value from the extracted choices', () => {
  const links = context?.extractUrls?.('https://one.example https://two.example');
  assert.equal(links?.length, 2);
  assert.equal(context?.chooseLink?.(links, ''), null);
  assert.equal(context?.chooseLink?.(links, 'https://outside.example/'), null);
  assert.equal(context?.chooseLink?.(links, links[1]), 'https://two.example/');
});

test('multiple-link picker selects the first radio after adding the group', async () => {
  const appSource = await readFile(new URL('../app/static/app.mjs', import.meta.url), 'utf8');
  const showLinkOptionsSource = appSource.match(/^function showLinkOptions\(links\) \{[\s\S]*?^\}/mu)?.[0];
  assert.ok(showLinkOptionsSource, 'app must define showLinkOptions');

  const selectedStages = [];
  class Element {
    constructor(tagName) {
      this.tagName = tagName;
      this.children = [];
      this._checked = false;
    }

    set checked(value) {
      this._checked = value;
      if (value) selectedStages.push(this.addedToRadioGroup);
    }

    get checked() {
      return this._checked;
    }

    append(...children) {
      this.children.push(...children);
    }

    replaceChildren() {
      this.children = [];
    }

    querySelector(selector) {
      if (selector !== 'input[name="selected-link"]') return null;
      return this.children.flatMap((label) => label.children)
        .find((child) => child.type === 'radio') || null;
    }

    scrollIntoView() {}
  }

  const options = new Element('div');
  options.append = (label) => {
    label.children[0].addedToRadioGroup = true;
    options.children.push(label);
  };
  const picker = new Element('div');
  const errorBox = new Element('p');
  const document = {
    createElement: (tagName) => new Element(tagName),
    querySelector: () => new Element('div'),
  };
  const showLinkOptions = runInNewContext(`(${showLinkOptionsSource})`, {
    document, options, picker, errorBox, selectedFlags: [], renderCuePills() {},
  });

  showLinkOptions(['https://example-one.example/login', 'https://example-two.example/pay']);

  const radios = options.children.map((label) => label.children[0]);
  assert.deepEqual(radios.map(({ value, checked }) => [value, checked]), [
    ['https://example-one.example/login', true],
    ['https://example-two.example/pay', false],
  ]);
  assert.deepEqual(selectedStages, [true], 'the default must be checked after joining the radio group');
});

test('detects context categories without returning the original text', () => {
  assert.equal(typeof context?.detectContextFlags, 'function', 'context module must export detectContextFlags');
  const result = context.detectContextFlags('Urgent: send your password and OTP, pay a ₹500 fee, and provide your Aadhaar number.');
  assert.deepEqual(result, ['urgency', 'credential_request', 'payment_request', 'personal_data_request']);
  assert.equal(JSON.stringify(result).includes('password'), false);
});

test('returns no context flags for ordinary text', () => {
  assert.deepEqual(context?.detectContextFlags?.('Here is the article we discussed.'), []);
});

test('analysis request contains the selected URL and cue flags, never message text', () => {
  const rawMessage = 'Urgent: send your password now. https://bank.example/login https://other.example/';
  const selectedUrl = context?.extractUrls?.(rawMessage)?.[0];
  const payload = context?.buildAnalyzeRequest?.(selectedUrl, 'local', false, context.detectContextFlags(rawMessage));

  assert.deepEqual(payload, {
    url: 'https://bank.example/login',
    mode: 'local',
    consent: false,
    context_flags: ['urgency', 'credential_request'],
  });
  assert.equal(JSON.stringify(payload).includes(rawMessage), false);
  assert.equal(JSON.stringify(payload).includes('password'), false);
  assert.equal('message' in payload, false);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function harness(fetch = async () => { throw new Error('unexpected fetch'); }) {
  const nodes = new Map();
  const get = id => {
    if (!nodes.has(id)) {
      nodes.set(id, {
        value: id === 'period' ? '168' : '',
        checked: true,
        innerHTML: '',
        textContent: '',
        hidden: false,
        open: false,
        disabled: false,
        classList: { add() {}, remove() {}, toggle() {} },
        querySelector() { return get(id + '-child'); },
        insertAdjacentHTML(_position, html) { this.innerHTML += html; }
      });
    }
    return nodes.get(id);
  };
  const context = vm.createContext({
    document: { getElementById: get, querySelectorAll: () => [], documentElement: { dataset: {} } },
    localStorage: { getItem: () => null, setItem: () => {} },
    window: { matchMedia: () => ({ matches: false }) },
    fetch,
    URLSearchParams,
    setTimeout,
    clearTimeout
  });
  const source = fs.readFileSync(path.join(__dirname, 'web/app.js'), 'utf8').split('/* Event Bindings */')[0];
  vm.runInContext(source + '\nglobalThis.app = { render, renderDetail, refresh, setState: value => state = value, getState: () => state };', context);
  return { app: context.app, get };
}

function fixture() {
  return {
    source: 'home',
    total_bytes: 5010,
    total_up: 501,
    total_down: 4509,
    total_domains: 120,
    visited_domains: 118,
    failure_only_domains: 1,
    probe_only_domains: 1,
    total_suggestions: 3,
    tested_domains: 5,
    level: 'l1',
    level_counts: { l1: 35, l2: 58, host: 120 },
    status_counts: { all: 35, pending: 22, passed: 3, direct: 6, ignored: 4 },
    ignored_domains: 4,
    ignored_rules: ['DOMAIN-SUFFIX,google.com'],
    git: { available: true, branch: 'main', head: 'abc1234', remote: 'origin', has_remote: true, changed_files: ['policy/rules/direct.list'], dirty_count: 1, ahead_count: 0 },
    routers: [
      { name: '10.10.10.1', target: 'admin@10.10.10.1', remote_path: '/containers/mihomo/config.yaml' },
      { name: '10.10.8.1', target: 'admin@10.10.8.1', remote_path: '/usb1/mihomo/config.yaml' }
    ],
    suggestion_counts: { direct_candidate: 3 },
    category_traffic: [{ name: 'google', up: 501, down: 4509 }],
    collection: { started_at: '0001-01-01T00:00:00Z', samples: 0, sample_errors: 0, active_connections: 0 },
    categories: [],
    overlaps: [],
    overlap_count: 0,
    tasks: [],
    attention: [
      {
        traffic: { host: 'bilibili.com', up: 100, down: 900, sample_rows: 2, failures: 0 },
        level: 'l1',
        child_count: 3,
        children: [{ host: 'api.bilibili.com' }, { host: 'i0.bilibili.com' }],
        match: { category: 'fallback', policy: '其他', rule: 'MATCH', priority: 0 },
        in_direct: false,
        ignored: false,
        direct_test: { domain: 'bilibili.com', passed: true, status: 200, duration_ms: 42 }
      }
    ],
    page: 1,
    pages: 2,
    report_limit: 50,
    filtered_domains: 35,
    report: {
      candidates: [],
      generated_at: '2026-11-12T00:00:00Z',
      since: '2026-11-05T00:00:00Z',
      evidence_since: '2026-11-05T00:00:00Z'
    }
  };
}

test('overview renders domain level counts, git dirty badge, router targets, and direct actions', () => {
  const { app, get } = harness();
  app.setState(fixture());
  app.render();
  assert.equal(get('stat-domains').textContent, '118');
  assert.equal(get('level-count-l1').textContent, 35);
  assert.equal(get('level-count-l2').textContent, 58);
  assert.equal(get('level-count-host').textContent, 120);
  assert.equal(get('chip-all').textContent, 35);
  assert.equal(get('chip-passed').textContent, 3);
  assert.equal(get('chip-ignored').textContent, 4);
  assert.equal(get('git-dirty-badge').hidden, false);
  assert.equal(get('git-dirty-badge').textContent, 1);
  assert.match(get('overview-table').innerHTML, /\+ 加入直连/);
  assert.match(get('overview-table').innerHTML, /直连通过 · 42 ms/);
  assert.match(get('router-targets').innerHTML, /admin@10\.10\.10\.1/);
  assert.match(get('router-targets').innerHTML, /admin@10\.10\.8\.1/);
  assert.equal(get('page-prev').disabled, true);
  assert.equal(get('page-next').disabled, false);
});

test('detail escapes unsafe host data and renders direct test results and child domains', () => {
  const { app, get } = harness();
  app.setState(fixture());
  app.renderDetail({
    traffic: { host: 'example.com', up: 10, down: 90, sample_rows: 1, failures: 0 },
    level: 'l1',
    child_count: 2,
    children: [
      { host: 'a.example.com', up: 10, down: 90, failures: 0, match: { category: 'fallback', policy: '其他' } }
    ],
    match: { category: 'fallback', policy: '其他', rule: 'MATCH', priority: 0 },
    current_route: 'DIRECT',
    direct_test: {
      domain: 'example.com',
      passed: true,
      duration_ms: 55,
      hosts: [{ host: 'a.example.com', resolved_ip: '1.2.3.4', passed: true, status: 200, duration_ms: 55 }]
    },
    evidence: [{ target: '<unsafe>', pairs: 20, direct_successes: 0, proxy_successes: 20, direct_p50_ms: null, direct_p95_ms: null, proxy_p50_ms: 200, proxy_p95_ms: 300, direct_errors: { 'tls:timeout': 20 } }]
  });
  assert.match(get('detail-body').innerHTML, /P50：无成功样本/);
  assert.match(get('detail-body').innerHTML, /Direct 测试结果/);
  assert.match(get('detail-body').innerHTML, /包含子域名/);
  assert.match(get('detail-body').innerHTML, /&lt;unsafe&gt;/);
  assert.doesNotMatch(get('detail-body').innerHTML, /<unsafe>/);
});

test('all literal element references in the script have matching markup and removed boilerplate stays absent', () => {
  const script = fs.readFileSync(path.join(__dirname, 'web/app.js'), 'utf8');
  const html = fs.readFileSync(path.join(__dirname, 'web/index.html'), 'utf8');
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
  for (const match of script.matchAll(/\$\('([^']+)'\)/g)) {
    assert.ok(ids.has(match[1]), `missing element: ${match[1]}`);
  }
  const banned = [
    '规则修改和发布仍由仓库管理，看板仅提供证据审阅。',
    '只统计进入 10.10.10.1 新 Mihomo 实例的连接',
    '清楚知道，谁先匹配。',
    '统一维护服务分类，解释规则重叠和最终命中。'
  ];
  for (const phrase of banned) {
    assert.ok(!html.includes(phrase), `banned boilerplate present in HTML: ${phrase}`);
    assert.ok(!script.includes(phrase), `banned boilerplate present in JS: ${phrase}`);
  }
});

test('a slow response for an old period cannot replace a newer selection', async () => {
  const pending = [];
  const { app, get } = harness(url => new Promise(resolve => pending.push({ url, resolve })));
  const old = app.refresh();
  get('period').value = '24';
  const current = app.refresh();
  assert.match(pending[1].url, /hours=24/);
  const latest = fixture();
  latest.status_counts.passed = 7;
  pending[1].resolve({ ok: true, json: async () => latest });
  await current;
  pending[0].resolve({ ok: true, json: async () => fixture() });
  await old;
  assert.equal(app.getState().status_counts.passed, 7);
  assert.equal(get('stat-suggestions').textContent, 7);
});

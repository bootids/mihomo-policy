'use strict';

const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const bytes = n => {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 4);
  return `${(n / 1024 ** i).toFixed(i > 0 ? 1 : 0)} ${u[i]}`;
};
const date = v => v ? new Date(v).toLocaleString('zh-CN', { hour12: false }) : '尚未执行';
const percent = v => `${Math.round((v || 0) * 100)}%`;

const pageTitles = {
  overview: '流量概览',
  candidates: '域名统计与直连',
  rules: '分类与规则',
  tasks: '发布与运行'
};

const levelNames = {
  l1: '一级域名',
  l2: '二级域名',
  host: '完整域名'
};

let state = null;
let refreshSequence = 0;
let detailSequence = 0;
let page = 1;
let currentLevel = 'l1';
let searchTimer = null;
let currentHost = '';
let currentDetailLevel = 'l1';
let toastTimer = null;
let sortState = { key: 'default', dir: 'desc' };
const testingDomains = new Set();
const mutatingDomains = new Set();

const candidates = () => state?.report?.candidates || [];
const duration = n => n == null ? '无成功样本' : `${n} ms`;
const routeName = route => ({ DIRECT: 'DIRECT', REJECT: '拦截', mixed: '混合出口', unverified: '代理出口', unknown: '无记录' }[route] || route);
const errorName = key => {
  const labels = {
    dns: 'DNS 异常', tls: 'TLS 失败', timeout: '超时', refused: '连接拒绝',
    unreachable: '不可达', unknown: '未知异常', connection_failed: '连接失败',
    certificate: '证书异常', unexpected_http_status: '状态码异常',
    content_mismatch: '内容不符', proxy_connect: '代理异常', cancelled: '已取消'
  };
  const parts = String(key || '').split(':');
  return parts.length === 2 ? `${parts[0].toUpperCase()} · ${labels[parts[1]] || parts[1]}` : (labels[key] || key);
};
const errorCounts = errors => Object.entries(errors || {}).map(([key, n]) => `${esc(errorName(key))} ${n}`).join('；') || '无';
const categoryTag = m => `<span class="tag ${m?.category === 'ai' ? 'ai' : m?.policy === 'DIRECT' ? 'green' : 'neutral'}">${esc(m?.category || 'fallback')}</span>`;

function domainStatusTag(c) {
  if (c.ignored) {
    return '<span class="tag neutral">已忽略</span>';
  }
  if (c.in_direct || c.match?.policy === 'DIRECT') {
    return '<span class="tag blue">已直连</span>';
  }
  if (c.direct_test) {
    if (c.direct_test.passed) {
      return `<span class="tag green">直连通过 · ${c.direct_test.duration_ms} ms</span>`;
    }
    const errText = c.direct_test.error ? ` · ${esc(errorName(c.direct_test.error))}` : '';
    return `<span class="tag danger">直连失败${errText}</span>`;
  }
  return '<span class="tag neutral">待测试</span>';
}

function domainActions(c, levelOverride = '') {
  const host = c.traffic?.host || c.host || '';
  const lvl = levelOverride || c.level || currentLevel;
  const ruleType = lvl === 'host' && host.split('.').length > 2 ? 'DOMAIN' : 'DOMAIN-SUFFIX';
  const busy = testingDomains.has(host) || mutatingDomains.has(host);
  const dis = busy ? 'disabled' : '';

  if (c.ignored) {
    return `<div class="row-actions">
      <button type="button" class="button mini ghost" data-action="unignore" data-domain="${esc(host)}" data-rule-type="${ruleType}" ${dis}>取消忽略</button>
    </div>`;
  }

  if (c.in_direct) {
    return `<div class="row-actions">
      <button type="button" class="button mini ghost" data-action="remove-direct" data-domain="${esc(host)}" data-rule-type="${ruleType}" ${dis}>移除直连</button>
    </div>`;
  }

  const testingLabel = testingDomains.has(host) ? '测试中…' : (c.direct_test ? '重测' : 'Direct 测试');
  const joinBtn = c.direct_test?.passed
    ? `<button type="button" class="button mini primary" data-action="add-direct" data-domain="${esc(host)}" data-rule-type="${ruleType}" ${dis}>+ 加入直连</button>`
    : '';

  return `<div class="row-actions">
    <button type="button" class="button mini" data-action="direct-test" data-domain="${esc(host)}" data-level="${esc(lvl)}" ${dis}>${testingLabel}</button>
    ${joinBtn}
    <button type="button" class="button mini ghost" data-action="ignore" data-domain="${esc(host)}" data-rule-type="${ruleType}" ${dis}>忽略</button>
  </div>`;
}

/* Theme Handling */
function initTheme() {
  const saved = localStorage.getItem('mihomo-policy-theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(saved || (prefersDark ? 'dark' : 'light'));
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const icon = $('theme-icon');
  if (!icon) return;
  if (theme === 'dark') {
    icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
  } else {
    icon.innerHTML = '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32l1.41-1.41"/>';
  }
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem('mihomo-policy-theme', next);
  applyTheme(next);
}

function showToast(msg) {
  const el = $('toast');
  if (!el) return;
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 2400);
}

/* Navigation */
function navigate() {
  const raw = location.hash.slice(1) || 'overview';
  const key = pageTitles[raw] ? raw : 'overview';
  document.querySelectorAll('.page').forEach(el => { el.hidden = el.id !== `page-${key}`; });
  document.querySelectorAll('nav a').forEach(el => el.classList.toggle('active', el.dataset.page === key));
  $('page-title').textContent = pageTitles[key];
  $('breadcrumb').textContent = pageTitles[key];
}

async function api(path, options = {}) {
  const init = { cache: 'no-store', credentials: 'same-origin', ...options };
  if (init.method && init.method !== 'GET') {
    init.headers = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'mihomo-policy',
      ...(init.headers || {})
    };
  }
  const response = await fetch(path, init);
  if (!response.ok) {
    const text = (await response.text()).trim();
    throw new Error(response.status === 401 ? '登录凭据已失效，请重新登录。' : (text || `请求失败（HTTP ${response.status}）`));
  }
  return response.json();
}

async function refresh(manual = false) {
  const sequence = ++refreshSequence;
  $('refresh').disabled = true;
  $('refresh-icon')?.classList.add('spinning');
  const params = new URLSearchParams({
    hours: $('period').value,
    level: currentLevel,
    page,
    q: $('search').value.trim(),
    category: $('category-filter').value,
    status: $('status-filter').value,
    sort: sortState.key,
    direction: sortState.dir
  });
  try {
    const next = await api(`/api/state?${params}`);
    if (sequence !== refreshSequence) return;
    state = next;
    page = state.page;
    $('error').hidden = true;
    render();
    if ($('detail-dialog').open && currentHost) showDetail(currentHost, currentDetailLevel);
    if (manual) showToast('已刷新');
  } catch (error) {
    if (sequence !== refreshSequence) return;
    $('error').textContent = error.message;
    $('error').hidden = false;
    $('connection').className = 'connection-pill warn';
    $('connection').textContent = '连接异常';
  } finally {
    if (sequence === refreshSequence) {
      $('refresh').disabled = false;
      $('refresh-icon')?.classList.remove('spinning');
    }
  }
}

function filterChanged() {
  clearTimeout(searchTimer);
  page = 1;
  refresh();
}

function render() {
  const health = state.collection || {};
  const fresh = health.last_sample && Date.now() - new Date(health.last_sample).getTime() < 15000;
  const standalone = health.started_at?.startsWith('0001');
  $('source').textContent = (state.source || 'home').toUpperCase();
  $('connection').className = `connection-pill ${fresh ? 'good' : 'warn'}`;
  $('connection').textContent = fresh ? '采集中' : standalone ? '离线数据' : '等待采样';

  const lc = state.level_counts || {};
  $('level-count-l1').textContent = lc.l1 ?? 0;
  $('level-count-l2').textContent = lc.l2 ?? 0;
  $('level-count-host').textContent = lc.host ?? state.total_domains ?? 0;

  const sc = state.status_counts || {};
  const passedCount = sc.passed ?? 0;
  const pendingCount = sc.pending ?? 0;
  const directCount = sc.direct ?? 0;
  const ignoredCount = sc.ignored ?? state.ignored_domains ?? 0;
  const allCount = sc.all ?? state.total_domains ?? 0;

  const gitChanges = (state.git?.dirty_count || 0) + (state.git?.ahead_count || 0);
  $('git-dirty-badge').hidden = gitChanges === 0;
  $('git-dirty-badge').textContent = gitChanges;

  $('stat-traffic').textContent = bytes(state.total_bytes);
  $('stat-traffic-sub').textContent = `↑ ${bytes(state.total_up)} · ↓ ${bytes(state.total_down)}`;
  $('stat-domains').textContent = (state.visited_domains ?? 0).toLocaleString();
  $('stat-domain-sub').textContent = `一级 ${lc.l1 ?? 0} · 二级 ${lc.l2 ?? 0} · 忽略仍计入统计`;
  $('stat-suggestions').textContent = passedCount;
  $('stat-suggestions-sub').textContent = `待评估 ${pendingCount} · 已直连 ${directCount} · 已忽略 ${ignoredCount}`;
  $('stat-collection').textContent = fresh ? '正常' : health.last_sample ? '中断' : standalone ? '离线' : '等待';
  $('stat-last-sample').textContent = health.last_sample ? `最近采样 ${date(health.last_sample)}` : '尚无实时采样';
  $('nav-count').textContent = passedCount || pendingCount;
  $('updated').textContent = `更新于 ${date(state.report?.generated_at)}`;

  const groups = (state.category_traffic || []).filter(c => c.up + c.down > 0);
  $('service-bars').innerHTML = groups.length ? groups.map(c => {
    const n = c.up + c.down;
    const share = state.total_bytes ? n / state.total_bytes * 100 : 0;
    return `<button type="button" class="bar-row" data-filter-category="${esc(c.name)}">
      <span class="bar-label">${esc(c.name)}</span>
      <progress class="bar-progress" max="100" value="${share}" aria-label="${esc(c.name)}"></progress>
      <span class="bar-meta">${bytes(n)}<span class="bar-pct">${share.toFixed(1)}%</span></span>
    </button>`;
  }).join('') : '<div class="empty"><strong>暂无流量数据</strong></div>';

  const denom = Math.max(1, allCount);
  const funnel = [
    [`${levelNames[currentLevel] || '域名'}总数`, allCount],
    ['待直连评估', pendingCount],
    ['测试通过（可加入直连）', passedCount],
    ['已直连规则覆盖', directCount],
    ['已忽略（保留统计）', ignoredCount]
  ];
  $('evidence-summary').innerHTML = funnel.map(([label, n]) =>
    `<div class="funnel-step"><div class="funnel-top"><span>${esc(label)}</span><strong>${Number(n || 0).toLocaleString()}</strong></div><progress class="funnel-progress" max="${denom}" value="${n || 0}"></progress></div>`
  ).join('');

  $('overview-table').innerHTML = table(state.attention || [], false);

  const filter = $('category-filter');
  const selected = filter.value;
  const categoryNames = [...new Set([...(state.category_traffic || []).map(c => c.name), ...(state.categories || []).map(c => c.name), selected].filter(Boolean))].sort();
  filter.innerHTML = '<option value="">全部分类</option>' + categoryNames.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
  filter.value = selected;

  $('chip-all').textContent = allCount;
  $('chip-pending').textContent = pendingCount;
  $('chip-passed').textContent = passedCount;
  $('chip-direct').textContent = directCount;
  $('chip-ignored').textContent = ignoredCount;

  renderCandidates();
  renderRules();
  renderTasks();
}

function sortHeader(label, key) {
  const active = sortState.key === key;
  const arrow = active ? (sortState.dir === 'asc' ? '↑' : '↓') : '↕';
  return `<button type="button" class="sort-btn ${active ? 'active' : ''}" data-sort="${key}">${label} <span class="sort-arrow">${arrow}</span></button>`;
}

function table(rows, sortable = true) {
  if (!rows.length) {
    return '<div class="empty"><strong>暂无符合条件的域名</strong></div>';
  }
  const lvlTitle = levelNames[currentLevel] || '域名';
  const showChildrenCol = currentLevel !== 'host';
  const head = sortable
    ? `<tr>
        <th>${sortHeader(lvlTitle, 'host')}</th>
        ${showChildrenCol ? `<th>${sortHeader('聚合子域', 'children')}</th>` : ''}
        <th>${sortHeader('命中分类 / 策略', 'category')}</th>
        <th>${sortHeader('流量', 'bytes')}</th>
        <th>${sortHeader('失败', 'failures')}</th>
        <th>状态</th>
        <th>操作</th>
      </tr>`
    : `<tr>
        <th>${lvlTitle}</th>
        ${showChildrenCol ? '<th>聚合子域</th>' : ''}
        <th>命中分类 / 策略</th>
        <th>流量</th>
        <th>失败</th>
        <th>状态</th>
        <th>操作</th>
      </tr>`;

  return `<table><thead>${head}</thead><tbody>` + rows.map(c => {
    const total = (c.traffic?.up || 0) + (c.traffic?.down || 0);
    const failCount = c.traffic?.failures || 0;
    const failClass = failCount > 0 ? 'has-fail' : 'zero';
    const childPreview = (c.children || []).slice(0, 2).map(ch => ch.host).filter(h => h !== c.traffic.host).join(', ');
    const childCount = c.child_count || 1;
    const lvl = c.level || currentLevel;
    return `<tr class="${c.ignored ? 'row-ignored' : ''}">
      <td>
        <div class="domain-cell">
          <button type="button" class="domain-button" data-host="${esc(c.traffic.host)}" data-level="${esc(lvl)}">${esc(c.traffic.host)}</button>
          ${childPreview ? `<span class="traffic-sub">${esc(childPreview)}${childCount > 2 ? ' …' : ''}</span>` : ''}
        </div>
      </td>
      ${showChildrenCol ? `<td class="mono">${childCount}</td>` : ''}
      <td>
        ${categoryTag(c.match)} <span class="muted">${esc(c.match?.policy || '')}</span>
        ${(c.child_categories?.length || 0) > 1 ? `<span class="traffic-sub">含 ${esc(c.child_categories.join(' / '))}</span>` : ''}
      </td>
      <td class="mono">
        <div class="traffic-cell">
          <span>${bytes(total)}</span>
          ${total > 0 ? `<span class="traffic-sub">↑${bytes(c.traffic.up)} ↓${bytes(c.traffic.down)}</span>` : ''}
        </div>
      </td>
      <td class="mono"><span class="fail-pill ${failClass}">${failCount}</span></td>
      <td>${domainStatusTag(c)}</td>
      <td>${domainActions(c, lvl)}</td>
    </tr>`;
  }).join('') + '</tbody></table>';
}

function renderCandidates() {
  const search = $('search').value.trim();
  const category = $('category-filter').value;
  const status = $('status-filter').value;
  $('clear-search').hidden = !search;
  $('reset-filters').hidden = !(search || category || status || sortState.key !== 'default');
  document.querySelectorAll('.quick-chips .chip').forEach(btn => btn.classList.toggle('active', btn.dataset.status === status));
  $('candidate-table').innerHTML = table(candidates(), true);
  $('table-count').textContent = `当前筛选 ${state.filtered_domains} 项 · 第 ${state.page} / ${state.pages} 页（每页 ${state.report_limit} 项）`;
  $('page-prev').disabled = state.page <= 1;
  $('page-next').disabled = state.page >= state.pages;
  $('page-number').textContent = `${state.page} / ${state.pages}`;
}

function renderRules() {
  const query = ($('rule-search')?.value || '').trim().toLowerCase();
  const cats = (state.categories || []).filter(c => {
    if (!query) return true;
    return c.name.toLowerCase().includes(query) ||
      c.policy.toLowerCase().includes(query) ||
      c.rules.some(r => r.toLowerCase().includes(query));
  });

  $('category-cards').innerHTML = cats.length
    ? cats.map(c => {
        const matchedRules = query ? c.rules.filter(r => r.toLowerCase().includes(query)) : c.rules;
        const displayRules = matchedRules.length ? matchedRules : c.rules;
        return `<article class="category-card">
          <div class="category-top">
            <h3>${esc(c.name)}</h3>
            <span class="priority">P${c.priority}</span>
          </div>
          <p>策略组 <strong>${esc(c.policy)}</strong> <span class="muted">· ${c.rule_count} 条</span></p>
          <details ${query && matchedRules.length ? 'open' : ''}>
            <summary>规则明细${c.rule_count > 150 ? '（前 150 条）' : ''}${query && matchedRules.length ? ` · 匹配 ${matchedRules.length} 条` : ''}</summary>
            <pre>${esc(displayRules.join('\n'))}</pre>
          </details>
        </article>`;
      }).join('')
    : '<div class="empty empty-span"><strong>未找到匹配的分类或规则</strong></div>';

  $('overlap-count').textContent = `${state.overlap_count || 0} 项`;
  $('overlaps').innerHTML = (state.overlaps || []).length
    ? '<table><thead><tr><th>高优先级</th><th>低优先级</th><th>高优先级规则</th><th>低优先级规则</th><th>类型</th></tr></thead><tbody>' +
      state.overlaps.map(o => `<tr>
        <td><strong>${esc(o.higher)}</strong></td>
        <td>${esc(o.lower)}</td>
        <td class="mono">${esc(o.higher_rule)}</td>
        <td class="mono">${esc(o.lower_rule)}</td>
        <td><span class="tag ${o.kind === 'full_shadow' ? 'amber' : 'neutral'}">${o.kind === 'full_shadow' ? '完全覆盖' : '部分交集'}</span></td>
      </tr>`).join('') + '</tbody></table>'
    : '<div class="empty"><strong>无跨分类重叠</strong></div>';
}

function renderTasks() {
  const git = state.git || {};
  const gitBadge = $('git-status-badge');
  const pendingChanges = (git.dirty_count || 0) + (git.ahead_count || 0);
  if (gitBadge) {
    gitBadge.className = `tag ${!git.available ? 'neutral' : pendingChanges > 0 ? 'amber' : 'green'}`;
    gitBadge.textContent = !git.available ? '未初始化 Git' : pendingChanges > 0 ? `待推送 (${pendingChanges})` : '已同步';
  }
  const gitRows = [
    ['分支 / HEAD', `${git.branch || 'main'} @ ${git.head || '未提交'}`],
    ['远端仓库', git.remote_url || (git.has_remote ? git.remote : '尚未配置 remote')],
    ['待提交文件', (git.changed_files || []).length ? git.changed_files.join(', ') : '无未提交修改'],
    ['待推送提交', `${git.ahead_count || 0} 个`],
    ['已忽略域名数', `${(state.ignored_rules || []).length} 条 (policy/ignore.list)`]
  ];
  $('git-details').innerHTML = gitRows.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd></div>`).join('');

  const routers = state.routers || [];
  $('router-targets').innerHTML = routers.map(r => `<div class="task-item">
    <div>
      <strong>${esc(r.target)}</strong>
      <span class="tag neutral">${esc(r.name)}</span>
    </div>
    <p class="mono">${esc(r.remote_path)}</p>
  </div>`).join('');

  const h = state.collection || {};
  const fresh = h.last_sample && Date.now() - new Date(h.last_sample).getTime() < 15000;
  const badge = $('collector-badge');
  if (badge) {
    badge.className = `tag ${fresh ? 'green' : h.sample_errors > 0 ? 'amber' : 'neutral'}`;
    badge.textContent = fresh ? '运行正常' : h.started_at?.startsWith('0001') ? '离线模式' : '等待采样';
  }

  const values = [
    ['数据源', state.source || '—'],
    ['Mihomo API', state.controller || '未配置'],
    ['最近采样', date(h.last_sample)],
    ['累计采样 / 错误', `${(h.samples || 0).toLocaleString()} / ${(h.sample_errors || 0).toLocaleString()}`],
    ['活动连接', (h.active_connections || 0).toLocaleString()],
    ['日志流', h.logs_connected ? '已连接' : '等待重连'],
    ['规则集版本', (state.report?.policy_version || '').slice(0, 16) || '—']
  ];
  $('collector-details').innerHTML = values.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd></div>`).join('');

  const titles = { probe: '后台配对探测', report: '分析报告快照', retention: '历史数据清理' };
  $('task-list').innerHTML = (state.tasks || []).map(t => `<div class="task-item">
    <div>
      <span>${titles[t.name] || esc(t.name)}</span>
      <span class="tag ${t.enabled ? 'green' : 'neutral'}">${t.enabled ? '启用' : '停用'}</span>
    </div>
    <p>周期 <span class="mono">${esc(t.interval || '—')}</span> · 上次执行 ${date(t.last_success)}</p>
  </div>`).join('');
}

async function showDetail(host, level = currentLevel) {
  currentHost = host;
  currentDetailLevel = level || currentLevel;
  const sequence = ++detailSequence;
  const hours = $('period').value;
  $('detail-level-label').textContent = (levelNames[currentDetailLevel] || 'DOMAIN').toUpperCase();
  $('detail-title').textContent = host;
  $('detail-body').textContent = '加载中…';
  if (!$('detail-dialog').open) $('detail-dialog').showModal();
  try {
    const c = await api(`/api/candidate?host=${encodeURIComponent(host)}&level=${encodeURIComponent(currentDetailLevel)}&hours=${hours}`);
    if (sequence !== detailSequence || !$('detail-dialog').open || hours !== $('period').value) return;
    renderDetail(c);
  } catch (error) {
    if (sequence === detailSequence && $('detail-dialog').open) $('detail-body').textContent = error.message;
  }
}

function renderDetail(c) {
  const total = (c.traffic?.up || 0) + (c.traffic?.down || 0);
  const body = $('detail-body');
  const lvl = c.level || currentDetailLevel || 'host';

  body.innerHTML = `<div class="dialog-tags">
      ${categoryTag(c.match)}
      ${domainStatusTag(c)}
      <span class="tag neutral">${esc(routeName(c.current_route))}</span>
      <div class="dialog-inline-actions">${domainActions(c, lvl)}</div>
    </div>
    <dl class="details-list">
      <div><dt>当前匹配规则</dt><dd class="mono">${esc(c.match?.rule || 'MATCH')} → ${esc(c.match?.policy || '—')}${c.match?.priority ? ` (P${c.match.priority})` : ''}</dd></div>
      <div><dt>活跃时间</dt><dd>${c.traffic?.first_seen ? date(c.traffic.first_seen) + ' — ' + date(c.traffic.last_seen) : '无流量记录'}</dd></div>
      <div><dt>累计流量</dt><dd>${bytes(total)}（↑ ${bytes(c.traffic?.up)} / ↓ ${bytes(c.traffic?.down)} · ${c.traffic?.sample_rows || 0} 次采样）</dd></div>
      <div><dt>失败记录</dt><dd>${c.traffic?.failures || 0} 次（${errorCounts(c.traffic?.failure_kinds)}）</dd></div>
      ${c.direct_rule ? `<div><dt>直连规则</dt><dd class="mono">${esc(c.direct_rule)}</dd></div>` : ''}
      ${c.ignore_rule ? `<div><dt>忽略规则</dt><dd class="mono">${esc(c.ignore_rule)}</dd></div>` : ''}
    </dl>`;

  if (c.direct_test) {
    const dt = c.direct_test;
    const hostRows = (dt.hosts || []).map(h =>
      `<tr>
        <td class="mono">${esc(h.host)}</td>
        <td class="mono">${esc(h.resolved_ip || '—')}</td>
        <td>${h.passed ? `<span class="tag green">HTTP ${h.status}</span>` : `<span class="tag danger">${esc(errorName((h.phase ? h.phase + ':' : '') + (h.error || 'failed')))}</span>`}</td>
        <td class="mono">${h.duration_ms} ms</td>
      </tr>`
    ).join('');
    body.insertAdjacentHTML('beforeend', `<article class="evidence-card">
      <div class="evidence-card-head">
        <h3>Direct 测试结果</h3>
        <span class="muted">${date(dt.at)}</span>
      </div>
      ${hostRows ? `<div class="table-wrap"><table><thead><tr><th>测试主机</th><th>解析 IP</th><th>状态</th><th>耗时</th></tr></thead><tbody>${hostRows}</tbody></table></div>` : `<p>耗时 ${dt.duration_ms} ms</p>`}
    </article>`);
  }

  const children = c.children || [];
  if (children.length > 1 || (children.length === 1 && children[0].host !== c.traffic.host)) {
    body.insertAdjacentHTML('beforeend', `<article class="evidence-card">
      <h3>包含子域名（${children.length}）</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>子域名</th><th>命中分类</th><th>流量</th><th>失败</th><th>操作</th></tr></thead>
          <tbody>
            ${children.map(ch => {
              const chRow = { traffic: { host: ch.host }, level: 'host', in_direct: ch.in_direct, ignored: ch.ignored, direct_test: ch.direct_test, match: ch.match };
              return `<tr>
                <td class="mono">${esc(ch.host)}</td>
                <td>${categoryTag(ch.match)} <span class="muted">${esc(ch.match?.policy || '')}</span></td>
                <td class="mono">${bytes((ch.up || 0) + (ch.down || 0))}</td>
                <td class="mono">${ch.failures || 0}</td>
                <td>${domainActions(chRow, 'host')}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
    </article>`);
  }

  const routes = c.traffic?.routes || [];
  if (routes.length) {
    body.insertAdjacentHTML('beforeend', `<article class="evidence-card">
      <h3>实际观测链路</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>链路 / 节点</th><th>命中规则</th><th>流量 / 占比</th><th>最近活跃</th></tr></thead>
          <tbody>${routes.map(v => `<tr>
            <td>${esc(v.route || '—')}<br><span class="muted">${esc(v.node || '—')}</span></td>
            <td class="mono">${esc(v.rule || '—')}</td>
            <td class="mono">${bytes(v.up + v.down)} (${total ? percent((v.up + v.down) / total) : '—'})</td>
            <td>${date(v.last_seen)}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
    </article>`);
  }

  const dims = c.traffic?.dimensions || [];
  if (dims.length) {
    body.insertAdjacentHTML('beforeend', `<details class="evidence-card">
      <summary>客户端与协议明细（${dims.length}）</summary>
      <div class="table-wrap">
        <table>
          <thead><tr><th>客户端</th><th>协议 / 地址族 / 端口</th><th>流量</th></tr></thead>
          <tbody>${dims.map(d => `<tr>
            <td class="mono">${esc(d.client || '—')}</td>
            <td class="mono">${esc(d.network || '—')} / ${esc(d.address_family === 'unknown' ? '—' : d.address_family)} / ${esc(d.port || '—')}</td>
            <td class="mono">${bytes(d.bytes)}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
    </details>`);
  }

  (c.evidence || []).forEach(e => {
    const ratio = (successes, n) => n ? `${successes}/${n}（${percent(successes / n)}）` : '0';
    body.insertAdjacentHTML('beforeend', `<article class="evidence-card">
      <div class="evidence-card-head"><h3>配对探测 · ${esc(e.target)}</h3></div>
      <div class="route-compare">
        ${[['DIRECT', 'direct', e.direct_successes, e.direct_p50_ms, e.direct_p95_ms, e.direct_errors], ['PROXY', 'proxy', e.proxy_successes, e.proxy_p50_ms, e.proxy_p95_ms, e.proxy_errors]].map(([name, key, successes, p50, p95, errors]) =>
          `<div class="route-box ${key}">
            <div class="route-box-head"><span>${name}</span><span>${ratio(successes, e.pairs)}</span></div>
            <progress class="route-progress ${key === 'proxy' ? 'proxy' : ''}" max="${Math.max(1, e.pairs)}" value="${successes}"></progress>
            <div class="route-latency">P50：${duration(p50)} · P95：${duration(p95)}</div>
            <p>错误：${errorCounts(errors)}</p>
          </div>`
        ).join('')}
      </div>
    </article>`);
  });
}

async function handleDomainAction(action, domain, level, ruleType) {
  if (!domain) return;
  if (action === 'direct-test') {
    testingDomains.add(domain);
    if (state) render();
    try {
      const res = await api('/api/direct-test', {
        method: 'POST',
        body: JSON.stringify({ domain, level: level || currentLevel, hours: Number($('period').value) || 168 })
      });
      showToast(res.passed ? `${domain} 直连通过 (${res.duration_ms} ms)` : `${domain} 直连失败 (${errorName(res.error || 'failed')})`);
    } catch (err) {
      showToast(`测试失败: ${err.message}`);
    } finally {
      testingDomains.delete(domain);
      await refresh();
    }
    return;
  }

  mutatingDomains.add(domain);
  if (state) render();
  try {
    if (action === 'add-direct' || action === 'remove-direct') {
      const add = action === 'add-direct';
      await api('/api/rules/direct', {
        method: 'POST',
        body: JSON.stringify({ domain, action: add ? 'add' : 'remove', rule_type: ruleType || 'DOMAIN-SUFFIX' })
      });
      showToast(add ? `已加入直连规则: ${domain}` : `已移除直连规则: ${domain}`);
    } else if (action === 'ignore' || action === 'unignore') {
      const add = action === 'ignore';
      await api('/api/rules/ignore', {
        method: 'POST',
        body: JSON.stringify({ domain, action: add ? 'add' : 'remove', rule_type: ruleType || 'DOMAIN-SUFFIX' })
      });
      showToast(add ? `已忽略: ${domain}` : `已取消忽略: ${domain}`);
    }
  } catch (err) {
    showToast(`操作失败: ${err.message}`);
  } finally {
    mutatingDomains.delete(domain);
    await refresh();
  }
}

async function runGitPush() {
  const btn = $('run-git-push');
  const out = $('git-push-output');
  btn.disabled = true;
  out.hidden = false;
  out.className = 'ops-output';
  out.textContent = '正在提交并推送到 GitHub…';
  try {
    const data = await api('/api/git/push', {
      method: 'POST',
      body: JSON.stringify({
        message: $('git-commit-msg').value.trim(),
        refresh_routers: $('git-refresh-providers').checked
      })
    });
    const r = data.result || {};
    const lines = [
      r.committed ? `已创建提交 ${r.commit_hash}：${r.message}` : `工作区无新增改动 (${r.commit_hash || 'HEAD'})`,
      r.pushed ? `已推送到 ${r.remote}/${r.branch}` : '未推送'
    ];
    if (data.providers_refreshed) {
      const refreshedSummary = Object.entries(data.providers_refreshed)
        .map(([router, names]) => `${router} (${(names || []).length} 个规则集)`)
        .join('，');
      if (refreshedSummary) lines.push(`已通知路由器刷新规则集：${refreshedSummary}`);
    }
    out.className = 'ops-output success';
    out.textContent = lines.join('\n');
    $('git-commit-msg').value = '';
    showToast('Git 提交并推送成功');
    await refresh();
    return true;
  } catch (err) {
    out.className = 'ops-output error';
    out.textContent = err.message;
    showToast(`Git 推送失败: ${err.message}`);
    return false;
  } finally {
    btn.disabled = false;
  }
}

async function runDeployRouters() {
  const btn = $('run-deploy-all');
  const out = $('deploy-output');
  btn.disabled = true;
  out.hidden = false;
  out.className = 'ops-output';
  out.textContent = '正在上传 config.yaml 到 admin@10.10.10.1 与 admin@10.10.8.1 并重载…';
  try {
    const data = await api('/api/routers/deploy', {
      method: 'POST',
      body: JSON.stringify({})
    });
    const lines = (data.results || []).map(r =>
      r.ok
        ? `✓ ${r.name} (${r.remote_path})：已上传 ${bytes(r.uploaded_bytes)}${r.reloaded ? ' · 热重载成功' : ''} · ${r.duration_ms} ms`
        : `✗ ${r.name}：${r.error}`
    );
    out.className = data.ok ? 'ops-output success' : 'ops-output error';
    out.textContent = lines.join('\n') || (data.error || '完成');
    showToast(data.ok ? '双路由配置更新完成' : '部分路由器更新失败');
    return data.ok;
  } catch (err) {
    out.className = 'ops-output error';
    out.textContent = err.message;
    showToast(`路由器同步失败: ${err.message}`);
    return false;
  } finally {
    btn.disabled = false;
  }
}

async function runMatchLookup(hostInput) {
  const host = hostInput.trim();
  if (!host) return;
  $('match-result').textContent = '查询中…';
  try {
    const m = await api(`/api/match?host=${encodeURIComponent(host)}`);
    $('match-result').innerHTML = `
      <div class="match-card">
        <div class="match-chain">
          <span class="mono"><strong>${esc(host.toLowerCase())}</strong></span>
          <span class="match-arrow">→</span>
          ${categoryTag(m)}
          <span class="match-arrow">→</span>
          <span class="tag green">${esc(m.policy)}</span>
          <span class="tag neutral">${m.priority ? 'P' + m.priority : '兜底'}</span>
        </div>
        <span class="match-rule-box">${esc(m.rule)}</span>
      </div>`;
  } catch (e) {
    $('match-result').innerHTML = `<span class="error-text">${esc(e.message)}</span>`;
  }
}

/* Event Bindings */
$('match-form').addEventListener('submit', event => {
  event.preventDefault();
  runMatchLookup($('match-host').value);
});

document.addEventListener('click', event => {
  const actionBtn = event.target.closest('button[data-action]');
  if (actionBtn) {
    handleDomainAction(actionBtn.dataset.action, actionBtn.dataset.domain, actionBtn.dataset.level, actionBtn.dataset.ruleType);
    return;
  }

  const hostBtn = event.target.closest('button[data-host]');
  if (hostBtn) {
    showDetail(hostBtn.dataset.host, hostBtn.dataset.level || currentLevel);
    return;
  }

  const levelBtn = event.target.closest('.level-btn');
  if (levelBtn) {
    const lvl = levelBtn.dataset.level;
    if (lvl && lvl !== currentLevel) {
      currentLevel = lvl;
      document.querySelectorAll('.level-btn').forEach(b => b.classList.toggle('active', b === levelBtn));
      page = 1;
      refresh();
    }
    return;
  }

  const sortBtn = event.target.closest('button[data-sort]');
  if (sortBtn && state) {
    const key = sortBtn.dataset.sort;
    if (sortState.key === key) {
      sortState.dir = sortState.dir === 'desc' ? 'asc' : 'desc';
    } else {
      sortState.key = key;
      sortState.dir = key === 'host' || key === 'category' ? 'asc' : 'desc';
    }
    filterChanged();
    return;
  }

  const chipBtn = event.target.closest('.quick-chips .chip');
  if (chipBtn && state) {
    $('status-filter').value = chipBtn.dataset.status;
    filterChanged();
    return;
  }

  const barBtn = event.target.closest('button[data-filter-category]');
  if (barBtn && state) {
    $('category-filter').value = barBtn.dataset.filterCategory;
    location.hash = '#candidates';
    filterChanged();
    return;
  }

  const sampleBtn = event.target.closest('button[data-sample]');
  if (sampleBtn) {
    $('match-host').value = sampleBtn.dataset.sample;
    runMatchLookup(sampleBtn.dataset.sample);
    return;
  }

  const periodBtn = event.target.closest('.period-btn');
  if (periodBtn) {
    const hours = periodBtn.dataset.hours;
    if ($('period').value !== hours) {
      $('period').value = hours;
      document.querySelectorAll('.period-btn').forEach(b => b.classList.toggle('active', b === periodBtn));
      page = 1;
      refresh(true);
    }
    return;
  }

  const gotoCard = event.target.closest('[data-goto]');
  if (gotoCard) {
    location.hash = `#${gotoCard.dataset.goto}`;
  }
});

document.addEventListener('keydown', event => {
  const tag = document.activeElement?.tagName;
  const typing = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';

  if (event.key === '/' && !typing && !$('detail-dialog').open) {
    event.preventDefault();
    const onRules = location.hash === '#rules';
    if (!onRules && location.hash !== '#candidates') {
      location.hash = '#candidates';
    }
    const targetInput = onRules ? $('rule-search') : $('search');
    targetInput?.focus();
    targetInput?.select();
    return;
  }

  if (!typing && !event.metaKey && !event.ctrlKey && !event.altKey && !$('detail-dialog').open) {
    const map = { '1': 'overview', '2': 'candidates', '3': 'rules', '4': 'tasks' };
    if (map[event.key]) {
      location.hash = `#${map[event.key]}`;
    } else if (event.key.toLowerCase() === 'r') {
      refresh(true);
    }
  }
});

$('open-git-dialog').addEventListener('click', () => {
  location.hash = '#tasks';
  $('git-commit-msg')?.focus();
});

$('open-deploy-dialog').addEventListener('click', async () => {
  location.hash = '#tasks';
  await runDeployRouters();
});

$('run-git-push').addEventListener('click', runGitPush);
$('run-deploy-all').addEventListener('click', runDeployRouters);
$('run-publish-all').addEventListener('click', async () => {
  $('run-publish-all').disabled = true;
  try {
    const ok = await runGitPush();
    if (ok) {
      await runDeployRouters();
    }
  } finally {
    $('run-publish-all').disabled = false;
  }
});

$('copy-host').addEventListener('click', async () => {
  if (!currentHost) return;
  try {
    await navigator.clipboard.writeText(currentHost);
    showToast(`已复制 ${currentHost}`);
  } catch {
    showToast('复制失败');
  }
});

$('explain-host').addEventListener('click', () => {
  if (!currentHost) return;
  $('detail-dialog').close();
  $('match-host').value = currentHost;
  location.hash = '#rules';
  runMatchLookup(currentHost);
});

$('close-dialog').addEventListener('click', () => $('detail-dialog').close());
$('detail-dialog').addEventListener('click', event => {
  if (event.target === $('detail-dialog')) {
    const r = event.target.getBoundingClientRect();
    if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) {
      event.target.close();
    }
  }
});

$('theme-toggle').addEventListener('click', toggleTheme);
$('refresh').addEventListener('click', () => refresh(true));
$('period').addEventListener('change', () => {
  page = 1;
  document.querySelectorAll('.period-btn').forEach(b => b.classList.toggle('active', b.dataset.hours === $('period').value));
  refresh(true);
});

$('clear-search').addEventListener('click', () => {
  $('search').value = '';
  $('search').focus();
  if (state) filterChanged();
});

$('reset-filters').addEventListener('click', () => {
  $('search').value = '';
  $('category-filter').value = '';
  $('status-filter').value = '';
  sortState = { key: 'default', dir: 'desc' };
  if (state) filterChanged();
});

$('search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(filterChanged, 250);
});
['category-filter', 'status-filter'].forEach(id => $(id).addEventListener('change', filterChanged));
$('page-prev').addEventListener('click', () => { page = Math.max(1, page - 1); refresh(); });
$('page-next').addEventListener('click', () => { page += 1; refresh(); });

$('rule-search')?.addEventListener('input', () => {
  if (state) renderRules();
});

$('export').addEventListener('click', () => {
  window.location.href = `/api/report?hours=${$('period').value}`;
});

window.addEventListener('hashchange', navigate);
initTheme();
navigate();
refresh();
setInterval(() => {
  if (!document.hidden && testingDomains.size === 0 && mutatingDomains.size === 0) refresh();
}, 30000);

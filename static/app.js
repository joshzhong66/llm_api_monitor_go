const ORDERED_VENDORS = [
  '全部',
  'ChatGPT / OpenAI',
  'Azure OpenAI',
  'Claude / Anthropic',
  'Gemini / Google AI',
  'Kimi / Moonshot',
  '百度 / 千帆',
  '腾讯 / 混元',
  '千问 / 通义',
  '豆包 / 火山引擎',
  'MiniMax',
  '智谱',
  'DeepSeek',
  'LLM API Proxy',
  'Mistral',
  'Cohere',
  'Grok / xAI',
  'Amazon Bedrock'
];

const NAV_ITEMS = [
  {id: 'apiSummary', label: 'API 消费汇总'},
  {id: 'webSummary', label: '网页消费汇总'},
  {id: 'userSummary', label: '用户消费汇总'},
  {id: 'userTotal', label: '用户总消费排行'},
  {id: 'apiSessions', label: 'API 会话日志'},
  {id: 'webSessions', label: '网页会话日志'},
  {id: 'apiRequests', label: 'API 请求明细'},
  {id: 'webRequests', label: '网页请求明细'},
  {id: 'quic', label: 'QUIC 诊断'},
  {id: 'interfaceTraffic', label: '接口流量'},
  {id: 'targets', label: '厂商域名'}
];

const AUTO_REFRESH_MS = 5000;
const SEARCH_DEBOUNCE_MS = 300;
const SESSION_PAGE_SIZE = 50;
const REQUEST_PAGE_SIZE = 100;
const QUIC_PAGE_SIZE = 100;
const REQUEST_TIMEOUT_MS = 60000;
const EXPORT_PAGE_SIZE = 1000;
const USER_SUMMARY_PAGE_SIZE = 100;
const STREAM_EXPORT_THRESHOLD = 5000;
const TIME_RANGE_OPTIONS = [
  {value: 5, label: '最近5分钟'},
  {value: 10, label: '近10分钟'},
  {value: 15, label: '近15分钟'},
  {value: 30, label: '近30分钟'},
  {value: 60, label: '近1小时'},
  {value: 720, label: '近12小时'},
  {value: 10080, label: '近7天'},
  {value: 0, label: '显示全部'},
];
const TIME_RANGE_OPTIONS_NO_ALL = TIME_RANGE_OPTIONS.filter(item => item.value !== 0);

function emptyPaged(pageSize) {
  return {
    items: [],
    total: 0,
    page: 1,
    page_size: pageSize,
    total_pages: 1,
  };
}

function emptyInterfaceTraffic() {
  return {
    available: true,
    iface: '',
    sample_seconds: 0,
    limit: 0,
    captured_at: '',
    rows: [],
    totals: {},
    message: '',
    raw_text: '',
  };
}

const state = {
  selectedVendor: '全部',
  selectedView: 'apiSummary',
  status: null,
  pipeline: null,
  summary: [],
  userSummaryPage: emptyPaged(USER_SUMMARY_PAGE_SIZE),
  userTotalPage: emptyPaged(USER_SUMMARY_PAGE_SIZE),
  logsPage: emptyPaged(SESSION_PAGE_SIZE),
  requestLogsPage: emptyPaged(REQUEST_PAGE_SIZE),
  transportEventsPage: emptyPaged(QUIC_PAGE_SIZE),
  interfaceTraffic: emptyInterfaceTraffic(),
  targets: [],
  loadErrors: [],
  loadedViews: {
    common: false,
    sessions: false,
    requests: false,
    quic: false,
    interfaceTraffic: false,
    targets: false,
    userSummary: false,
    userTotal: false,
  },
  search: {
    summary: '',
    sessions: '',
    requests: '',
    quic: '',
    userSummary: '',
    userTotal: '',
  },
  hideEmpty: {
    sessions: true,
    requests: true,
  },
  pagination: {
    apiSessions: 1,
    webSessions: 1,
    apiRequests: 1,
    webRequests: 1,
    quic: 1,
    userSummary: 1,
    userTotal: 1,
  },
  timeRanges: {
    sessions: 5,
    requests: 5,
    quic: 5,
    userSummary: 5,
    userTotal: 5,
  },
  requestSeq: {
    apiSessions: 0,
    webSessions: 0,
    apiRequests: 0,
    webRequests: 0,
    quic: 0,
    interfaceTraffic: 0,
    userSummary: 0,
    userTotal: 0,
  },
};

const searchTimers = {};

const MATCH_TYPE_LABELS = {
  exact: '精确匹配',
  wildcard: '通配匹配',
};

const SOURCE_LABELS = {
  official: '官方域名',
  custom: '自定义规则',
  legacy: '兼容历史地址',
};

const CHANNEL_LABELS = {
  api: 'API 调用',
  api_quic: 'API / QUIC',
  web: '网页版',
  web_quic: '网页版 / QUIC',
  unknown: '未识别',
};

function isSessionView(view) {
  return view === 'apiSessions' || view === 'webSessions';
}

function isRequestView(view) {
  return view === 'apiRequests' || view === 'webRequests';
}

function viewGroup(view) {
  if (isSessionView(view)) return 'sessions';
  if (isRequestView(view)) return 'requests';
  if (view === 'quic') return 'quic';
  if (view === 'interfaceTraffic') return 'interfaceTraffic';
  if (view === 'targets') return 'targets';
  if (view === 'userSummary') return 'userSummary';
  if (view === 'userTotal') return 'userTotal';
  return 'summary';
}

function viewChannelClass(view) {
  if (view === 'apiSessions' || view === 'apiRequests') return 'api';
  if (view === 'webSessions' || view === 'webRequests') return 'web';
  return '';
}

function detailTitle(view) {
  if (view === 'apiSessions') return 'API 会话日志';
  if (view === 'webSessions') return '网页会话日志';
  if (view === 'apiRequests') return 'API 请求明细';
  if (view === 'webRequests') return '网页请求明细';
  if (view === 'quic') return 'QUIC 诊断';
  return '';
}

function timeRangeLabel(minutes) {
  const hit = TIME_RANGE_OPTIONS.find(item => Number(item.value) === Number(minutes));
  return hit ? hit.label : '显示全部';
}

async function request(path, options) {
  const fetchPromise = fetch(path, options || {});
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`request timeout: ${path}`)), REQUEST_TIMEOUT_MS);
  });
  const res = await Promise.race([fetchPromise, timeoutPromise]);
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    throw new Error((data && data.message) || `request failed: ${path}`);
  }
  return data;
}

function numberFmt(value) {
  return Number(value || 0).toLocaleString('zh-CN');
}

function moneyFmt(value) {
  return Number(value || 0).toFixed(6);
}

function estimatedCostValue(row) {
  if (row && row.estimated_cost_usd != null) return row.estimated_cost_usd;
  return row ? row.estimated_cost_cny : 0;
}

function bytesFmt(value) {
  const num = Number(value || 0);
  if (num >= 1024 * 1024 * 1024) return `${(num / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (num >= 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(2)} MB`;
  if (num >= 1024) return `${(num / 1024).toFixed(2)} KB`;
  return `${num} B`;
}

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function filteredRows(rows) {
  if (state.selectedVendor === '全部') return rows;
  return rows.filter(row => row.vendor === state.selectedVendor);
}

function searchKeyword(value) {
  return String(value || '').trim().toLowerCase();
}

function searchRows(rows, keyword) {
  const needle = searchKeyword(keyword);
  if (!needle) return rows;
  return rows.filter(row => Object.keys(row).some(key => String(row[key] == null ? '' : row[key]).toLowerCase().indexOf(needle) !== -1));
}

function normalizePagedPayload(payload, fallbackPage, fallbackPageSize) {
  const safePage = Math.max(1, Number(fallbackPage || 1));
  const safePageSize = Math.max(1, Number(fallbackPageSize || 1));
  if (Array.isArray(payload)) {
    const total = payload.length;
    const totalPages = Math.max(1, Math.ceil(total / safePageSize));
    const currentPage = Math.min(safePage, totalPages);
    const start = (currentPage - 1) * safePageSize;
    return {
      items: payload.slice(start, start + safePageSize),
      total,
      page: currentPage,
      page_size: safePageSize,
      total_pages: totalPages,
    };
  }
  if (payload && Array.isArray(payload.items)) {
    return {
      items: payload.items,
      total: Number(payload.total || 0),
      page: Math.max(1, Number(payload.page || safePage)),
      page_size: Math.max(1, Number(payload.page_size || safePageSize)),
      total_pages: Math.max(1, Number(payload.total_pages || 1)),
    };
  }
  return emptyPaged(safePageSize);
}

function summaryRowsBase() {
  const vendorRows = filteredRows(state.summary);
  if (state.selectedView === 'webSummary') {
    return vendorRows.filter(row => row.channel_type !== 'api');
  }
  return vendorRows.filter(row => row.channel_type === 'api');
}

function summaryRows() {
  return searchRows(summaryRowsBase(), state.search.summary);
}

function sessionRows() {
  return state.logsPage.items;
}

function requestRows() {
  return state.requestLogsPage.items;
}

function quicRows() {
  return state.transportEventsPage.items;
}

function interfaceTrafficRows() {
  return state.interfaceTraffic.rows || [];
}

function searchMetaText(totalRows, matchedRows, keyword, pageText) {
  const base = keyword
    ? `当前共 ${numberFmt(totalRows)} 条，搜索“${keyword}”匹配 ${numberFmt(matchedRows)} 条`
    : `当前共 ${numberFmt(totalRows)} 条`;
  return pageText ? `${base}，${pageText}` : base;
}

function detailMetaText(payload, keyword, includeVendor) {
  const filters = [];
  if (includeVendor && state.selectedVendor !== '全部') {
    filters.push(`厂商 ${state.selectedVendor}`);
  }
  if (keyword) {
    filters.push(`搜索“${keyword}”`);
  }
  const base = filters.length
    ? `${filters.join('，')} 匹配 ${numberFmt(payload.total)} 条`
    : `当前共 ${numberFmt(payload.total)} 条`;
  return `${base}，第 ${numberFmt(payload.page)} / ${numberFmt(payload.total_pages)} 页，每页 ${numberFmt(payload.page_size)} 条`;
}

function secondsFmt(value) {
  const seconds = Number(value || 0);
  if (seconds >= 60) {
    return `${(seconds / 60).toFixed(1)} 分钟`;
  }
  return `${seconds.toFixed(1)} 秒`;
}

function channelLabel(value) {
  return CHANNEL_LABELS[value] || value || '-';
}

function pipelineHintText(status) {
  const metrics = status && status.pipeline_metrics;
  if (!metrics) {
    return '请求明细显示延迟由抓包分段、解析入库和页面自动刷新共同决定。';
  }
  const latestParsed = metrics.latest_parsed_at ? `，最近一次解析完成于 ${metrics.latest_parsed_at}` : '';
  return `预计从抓包到页面可见：平均约 ${secondsFmt(metrics.avg_visible_seconds)}，最长约 ${secondsFmt(metrics.max_visible_seconds)}。计算基于最近 ${numberFmt(metrics.sample_jobs)} 个已解析分段，包含分段等待、解析入库和 ${metrics.refresh_seconds} 秒页面自动刷新${latestParsed}。`;
}

function requestPanelHintText(status, keyword) {
  const suffix = keyword ? ` 当前搜索词为“${keyword}”。` : '';
  return `${pipelineHintText(status)}${suffix} 若超过预计可见延迟仍无结果，通常表示当前没有命中规则的数据包，或流量走成了未识别的 QUIC / 长连接复用。`;
}

function quicHintText(payload) {
  return `这里集中展示 UDP/443 / QUIC 诊断流量。对部分已知 API 域名，系统会按目标 IP 做提示识别；但 QUIC 仍无法像 TCP 一样稳定还原每次请求明细。当前匹配 ${numberFmt(payload.total)} 条。`;
}

function interfaceTrafficHintText(payload) {
  if (!payload || payload.available === false) {
    return `当前无法获取接口实时流量。${payload && payload.message ? payload.message : '请确认 iftop 已安装且当前进程具备抓取权限。'}`;
  }
  const iface = payload.iface || (state.status && state.status.iface) || '-';
  const sample = Number(payload.sample_seconds || 0);
  const capturedAt = payload.captured_at || '-';
  return `数据来自 iftop -i ${iface} 的最近 ${sample} 秒观测窗口，页面自动刷新时会重新采样。最近采样时间：${capturedAt}。`;
}

function iftopRateCell(label, rates) {
  const safe = rates || {};
  return `
    <div class="rate-stack">
      <div><span>${label}</span><strong>${safe.last_2s || '0B'}</strong></div>
      <div><span>10s</span><strong>${safe.last_10s || '0B'}</strong></div>
      <div><span>40s</span><strong>${safe.last_40s || '0B'}</strong></div>
      <div><span>累计</span><strong>${safe.cumulative || '0B'}</strong></div>
    </div>
  `;
}

function iftopSummaryCard(title, rates) {
  const safe = rates || {};
  return `
    <article class="traffic-metric-card">
      <p>${title}</p>
      <strong>${safe.last_2s || '0B'}</strong>
      <span>10s ${safe.last_10s || '0B'}</span>
      <span>40s ${safe.last_40s || '0B'}</span>
    </article>
  `;
}

function filenameTimestamp() {
  const now = new Date();
  const pad = value => (value < 10 ? `0${value}` : String(value));
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}_${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

function csvFilename(kind) {
  return `${filenameTimestamp()}_model_monitor_${kind}.csv`;
}

function statusBadge(running) {
  return `<span class="badge ${running ? 'running' : 'stopped'}">${running ? '运行中' : '已停止'}</span>`;
}

function heroStatusText(status) {
  if (!status) return '载入中';
  if (status.capture_running) return '持续抓包中';
  if (status.parser_running) return '正在补解析';
  return '后台未采集';
}

function currentViewTitle() {
  if (state.selectedView === 'apiSummary') return 'API 消费汇总';
  if (state.selectedView === 'webSummary') return '网页消费汇总';
  if (state.selectedView === 'apiSessions') return 'API 会话日志';
  if (state.selectedView === 'webSessions') return '网页会话日志';
  if (state.selectedView === 'apiRequests') return 'API 请求明细';
  if (state.selectedView === 'webRequests') return '网页请求明细';
  if (state.selectedView === 'quic') return 'QUIC 诊断';
  if (state.selectedView === 'interfaceTraffic') return '接口实时流量';
  return '厂商域名';
}

function summaryPanelTitle() {
  return state.selectedView === 'webSummary' ? '网页消费汇总' : 'API 消费汇总';
}

function labelMatchType(value) {
  return MATCH_TYPE_LABELS[value] || value || '-';
}

function labelSource(value) {
  return SOURCE_LABELS[value] || value || '-';
}

function setLoadError(label, failed) {
  const idx = state.loadErrors.indexOf(label);
  if (failed && idx === -1) state.loadErrors.push(label);
  if (!failed && idx !== -1) state.loadErrors.splice(idx, 1);
}

function buildQuery(params) {
  const qs = new URLSearchParams();
  Object.keys(params).forEach(key => {
    const value = params[key];
    if (value == null || value === '') return;
    qs.set(key, String(value));
  });
  const text = qs.toString();
  return text ? `?${text}` : '';
}

function currentDatasetRows() {
  if (state.selectedView === 'apiSummary' || state.selectedView === 'webSummary') return summaryRows();
  if (isSessionView(state.selectedView)) return sessionRows();
  if (isRequestView(state.selectedView)) return requestRows();
  if (state.selectedView === 'quic') return quicRows();
  if (state.selectedView === 'interfaceTraffic') return interfaceTrafficRows();
  return [];
}

function renderSidebar() {
  const status = state.status;
  const targetVendorCount = state.targets.length;
  const targetDomainCount = state.targets.reduce((sum, item) => sum + item.domains.length, 0);
  document.getElementById('sidebarStatus').innerHTML = `
    <div class="sidebar-pill ${status && status.running ? 'running' : 'stopped'}">${heroStatusText(status)}</div>
    <div class="sidebar-meta">
      <span>${status && status.iface ? status.iface : '-'}</span>
      <span>${status && status.window_seconds ? status.window_seconds : 0} 秒分段</span>
      <span>${targetVendorCount} 个厂商</span>
      <span>${targetDomainCount} 条域名规则</span>
    </div>
  `;
  document.getElementById('sidebarNav').innerHTML = NAV_ITEMS.map(item => `
    <button class="nav-button ${state.selectedView === item.id ? 'active' : ''}" data-view="${item.id}">${item.label}</button>
  `).join('');
  Array.prototype.forEach.call(document.querySelectorAll('[data-view]'), node => {
    node.addEventListener('click', () => {
      state.selectedView = node.getAttribute('data-view');
      if (isSessionView(state.selectedView)) state.pagination[state.selectedView] = Math.max(1, state.pagination[state.selectedView] || 1);
      if (isRequestView(state.selectedView)) state.pagination[state.selectedView] = Math.max(1, state.pagination[state.selectedView] || 1);
      if (state.selectedView === 'quic') state.pagination.quic = 1;
      renderAll();
      refreshAll(true).catch(() => renderAll());
    });
  });
}

function pipelineChips() {
  const p = state.pipeline;
  if (!p) return '<span class="meta-chip">管道: 加载中</span>';
  const lag = pipelineLag(p);
  const lagClass = lag <= 60 ? 'ok' : lag <= 300 ? 'warn' : 'error';
  const lagText = lag <= 60 ? lag + 's' : lag < 3600 ? Math.floor(lag/60) + 'm' + (lag%60) + 's' : Math.floor(lag/3600) + 'h' + Math.floor(lag%3600/60) + 'm';
  const pending = p.pending_jobs || 0;
  let chips = `<span class="meta-chip pipeline-${lagClass}">延迟 ${lagText}</span>`;
  chips += `<span class="meta-chip">已解析 ${p.progress_pct || 0}% (${numberFmt(p.merged_jobs || 0)}/${numberFmt(p.total_jobs || 0)})</span>`;
  if (pending > 0) chips += `<span class="meta-chip pipeline-warn">待处理 ${numberFmt(pending)}</span>`;
  if (p.failed_jobs > 0) chips += `<span class="meta-chip pipeline-error">失败 ${numberFmt(p.failed_jobs)}</span>`;
  return chips;
}

function pipelineLag(p) {
  if (!p || !p.latest_data || !p.server_time) return 0;
  const latest = new Date(p.latest_data.replace(' ', 'T') + '+08:00');
  const server = new Date(p.server_time.replace(' ', 'T') + '+08:00');
  return Math.max(0, Math.floor((server - latest) / 1000));
}

function renderHero() {
  const status = state.status;
  if (state.selectedView === 'interfaceTraffic') {
    const payload = state.interfaceTraffic || emptyInterfaceTraffic();
    const totals = payload.totals || {};
    const combinedRate = totals.combined_rate || {};
    const sendRate = totals.send_rate || {};
    const receiveRate = totals.receive_rate || {};
    const cumulative = totals.cumulative || {};
    document.getElementById('heroStatus').className = `status-pill ${status && status.running ? 'running' : 'stopped'}`;
    document.getElementById('heroStatus').textContent = heroStatusText(status);
    document.getElementById('heroViewTitle').textContent = currentViewTitle();
    document.getElementById('heroStats').innerHTML = `
      <span class="meta-chip">接口 ${escapeHtml(payload.iface || (status && status.iface) || '-')}</span>
      <span class="meta-chip">Top 流 ${numberFmt(interfaceTrafficRows().length)}</span>
      <span class="meta-chip">总速率 ${escapeHtml(combinedRate.last_2s || '0B')}</span>
      <span class="meta-chip">发送 ${escapeHtml(sendRate.last_2s || '0B')}</span>
      <span class="meta-chip">接收 ${escapeHtml(receiveRate.last_2s || '0B')}</span>
      <span class="meta-chip">累计 ${escapeHtml(cumulative.last_40s || '0B')}</span>
    `;
    return;
  }
  const rows = currentDatasetRows();
  const totalSessions = rows.reduce((sum, row) => sum + Number(row.session_count || 0), 0);
  const totalRequests = rows.reduce((sum, row) => sum + Number(row.request_count || row.packet_count || 0), 0);
  const totalTraffic = rows.reduce((sum, row) => sum + Number(row.total_bytes || 0), 0);
  const totalTokens = rows.reduce((sum, row) => sum + Number(row.total_tokens || 0), 0);
  document.getElementById('heroStatus').className = `status-pill ${status && status.running ? 'running' : 'stopped'}`;
  document.getElementById('heroStatus').textContent = heroStatusText(status);
  document.getElementById('heroViewTitle').textContent = currentViewTitle();
  document.getElementById('heroStats').innerHTML = `
    <span class="meta-chip">当前记录 ${numberFmt(rows.length)}</span>
    <span class="meta-chip">累计会话 ${numberFmt(totalSessions)}</span>
    <span class="meta-chip">累计请求 ${numberFmt(totalRequests)}</span>
    <span class="meta-chip">累计流量 ${bytesFmt(totalTraffic)}</span>
    <span class="meta-chip">累计 Token ${numberFmt(totalTokens)}</span>
    ${pipelineChips()}
  `;
}

function renderVendorFilters() {
  const vendorSet = new Set(ORDERED_VENDORS.slice(1));
  state.summary.forEach(row => vendorSet.add(row.vendor));
  state.logsPage.items.forEach(row => vendorSet.add(row.vendor));
  state.requestLogsPage.items.forEach(row => vendorSet.add(row.vendor));
  state.targets.forEach(row => vendorSet.add(row.vendor));
  const vendors = ['全部'].concat(Array.from(vendorSet).sort((a, b) => {
    const ai = ORDERED_VENDORS.indexOf(a);
    const bi = ORDERED_VENDORS.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  }));
  document.getElementById('vendorFilters').innerHTML = vendors.map(vendor => `
    <button class="filter-chip ${state.selectedVendor === vendor ? 'active' : ''}" data-vendor="${escapeHtml(vendor)}">${escapeHtml(vendor)}</button>
  `).join('');
  Array.prototype.forEach.call(document.querySelectorAll('[data-vendor]'), node => {
    node.addEventListener('click', () => {
      state.selectedVendor = node.getAttribute('data-vendor');
      state.pagination.apiSessions = 1;
      state.pagination.webSessions = 1;
      state.pagination.apiRequests = 1;
      state.pagination.webRequests = 1;
      state.pagination.quic = 1;
      state.pagination.userSummary = 1;
      state.pagination.userTotal = 1;
      renderAll();
      if (isSessionView(state.selectedView) || isRequestView(state.selectedView) || state.selectedView === 'quic' || state.selectedView === 'userSummary' || state.selectedView === 'userTotal') {
        refreshViewData(state.selectedView, true).then(renderAll).catch(() => renderAll());
      }
    });
  });
}

function renderSystemMeta() {
  const status = state.status;
  const metrics = status && status.pipeline_metrics;
  const meta = [
    statusBadge(status && status.running),
    `<span class="meta-chip">网卡 ${status && status.iface ? status.iface : '-'}</span>`,
    `<span class="meta-chip">抓包 ${status && status.capture_running ? '进行中' : '已停止'}</span>`,
    `<span class="meta-chip">解析 ${status && status.parser_running ? '进行中' : '空闲'}</span>`,
    `<span class="meta-chip">活跃会话 ${status && status.active_sessions ? status.active_sessions : 0}</span>`
  ];
  if (metrics) {
    meta.push(`<span class="meta-chip">明细可见延迟 ${secondsFmt(metrics.avg_visible_seconds)} ~ ${secondsFmt(metrics.max_visible_seconds)}</span>`);
  }
  document.getElementById('statusMeta').innerHTML = meta.join('');
  document.getElementById('pipelineHint').textContent = pipelineHintText(status);
  document.getElementById('refreshHint').textContent = `最近刷新 ${new Date().toLocaleTimeString('zh-CN')}`;
}

function renderPageAlert() {
  const host = document.getElementById('pageAlert');
  if (!state.loadErrors.length) {
    host.textContent = '';
    host.className = 'alert-banner hidden';
    return;
  }
  host.textContent = `部分数据暂时加载失败：${state.loadErrors.join('；')}。页面先展示已成功返回的数据，稍后会自动重试。`;
  host.className = 'alert-banner';
}

function showToast(message, type) {
  const existing = document.querySelector('.toast-notification');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = 'toast-notification toast-' + (type || 'info');
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function localToServerDateTime(value) {
  if (!value) return '';
  return value.replace('T', ' ') + ':00';
}

function renderSummary() {
  const root = document.getElementById('summarySection');
  root.classList.toggle('hidden', !(state.selectedView === 'apiSummary' || state.selectedView === 'webSummary'));
  if (root.classList.contains('hidden')) return;
  document.getElementById('summaryPanelTitle').textContent = summaryPanelTitle();
  const totalRows = summaryRowsBase().length;
  const rows = summaryRows();
  const body = document.getElementById('summaryBody');
  document.getElementById('summarySearchMeta').textContent = searchMetaText(totalRows, rows.length, state.search.summary);
  if (!rows.length) {
    body.innerHTML = '<tr><td class="empty-cell" colspan="13">当前筛选条件下暂无汇总记录</td></tr>';
    return;
  }
  body.innerHTML = rows.map(row => `
    <tr>
      <td><span class="vendor-tag">${escapeHtml(row.vendor)}</span></td>
      <td class="mono">${escapeHtml(row.domain)}</td>
      <td>${escapeHtml(channelLabel(row.channel_type))}</td>
      <td>${numberFmt(row.session_count)}</td>
      <td>${numberFmt(row.request_count)}</td>
      <td>${bytesFmt(row.uplink_bytes)}</td>
      <td>${bytesFmt(row.downlink_bytes)}</td>
      <td>${bytesFmt(row.total_bytes)}</td>
      <td>${numberFmt(row.input_tokens)}</td>
      <td>${numberFmt(row.output_tokens)}</td>
      <td>${numberFmt(row.total_tokens)}</td>
      <td>${moneyFmt(estimatedCostValue(row))}</td>
      <td>${escapeHtml(row.latest_seen || '-')}</td>
    </tr>
  `).join('');
}

function renderPagination(hostId, payload, prefix, onChange) {
  const host = document.getElementById(hostId);
  if (payload.total_pages <= 1) {
    host.innerHTML = '';
    return;
  }
  host.innerHTML = `
    <button class="ghost page-button" ${payload.page <= 1 ? 'disabled' : ''} data-page-action="${prefix}:prev">上一页</button>
    <span class="pagination-text">第 ${numberFmt(payload.page)} / ${numberFmt(payload.total_pages)} 页，每页 ${numberFmt(payload.page_size)} 条</span>
    <button class="ghost page-button" ${payload.page >= payload.total_pages ? 'disabled' : ''} data-page-action="${prefix}:next">下一页</button>
  `;
  Array.prototype.forEach.call(host.querySelectorAll('[data-page-action]'), node => {
    node.addEventListener('click', () => {
      const action = node.getAttribute('data-page-action');
      if (action === `${prefix}:prev`) onChange(payload.page - 1);
      if (action === `${prefix}:next`) onChange(payload.page + 1);
    });
  });
}

function renderTimeRangeFilters(hostId, group, options) {
  const rangeOptions = options || TIME_RANGE_OPTIONS;
  const host = document.getElementById(hostId);
  const currentValue = Number(state.timeRanges[group] || 0);
  host.innerHTML = rangeOptions.map(item => `
    <button class="filter-chip ${currentValue === Number(item.value) ? 'active' : ''}" type="button" data-time-range="${group}:${item.value}">${item.label}</button>
  `).join('');
  Array.prototype.forEach.call(host.querySelectorAll('[data-time-range]'), node => {
    node.addEventListener('click', () => {
      const parts = node.getAttribute('data-time-range').split(':');
      const nextGroup = parts[0];
      const nextValue = Number(parts[1] || 0);
      if (nextValue === 0 && !confirm('显示全部数据可能导致加载缓慢或页面卡顿，确认继续？')) {
        return;
      }
      state.timeRanges[nextGroup] = nextValue;
      if (nextGroup === 'sessions') {
        state.pagination.apiSessions = 1;
        state.pagination.webSessions = 1;
      }
      if (nextGroup === 'requests') {
        state.pagination.apiRequests = 1;
        state.pagination.webRequests = 1;
      }
      if (nextGroup === 'quic') {
        state.pagination.quic = 1;
      }
      if (nextGroup === 'userSummary') {
        state.pagination.userSummary = 1;
      }
      if (nextGroup === 'userTotal') {
        state.pagination.userTotal = 1;
      }
      renderAll();
      refreshViewData(state.selectedView, true).then(renderAll).catch(() => renderAll());
    });
  });
}

function renderSessionLogs() {
  const root = document.getElementById('sessionSection');
  root.classList.toggle('hidden', !isSessionView(state.selectedView));
  if (root.classList.contains('hidden')) return;
  document.getElementById('sessionPanelTitle').textContent = detailTitle(state.selectedView);
  renderTimeRangeFilters('sessionTimeFilters', 'sessions');
  const payload = state.logsPage;
  const rows = sessionRows();
  const body = document.getElementById('sessionLogBody');
  document.getElementById('sessionSearchMeta').textContent = `${detailMetaText(payload, state.search.sessions, true)}，时间范围 ${timeRangeLabel(state.timeRanges.sessions)}`;
  if (!rows.length) {
    body.innerHTML = '<tr><td class="empty-cell" colspan="16">当前筛选条件下暂无会话日志</td></tr>';
    renderPagination('sessionPagination', payload, 'session', page => changePage(state.selectedView, page));
    return;
  }
  body.innerHTML = rows.map(row => `
    <tr>
      <td>${escapeHtml(row.iface)}</td>
      <td class="mono">${escapeHtml(row.src_ip)}</td>
      <td>${escapeHtml(row.src_user || '-')}</td>
      <td>${escapeHtml(row.first_seen || '-')}</td>
      <td>${escapeHtml(row.last_seen || '-')}</td>
      <td>${escapeHtml(channelLabel(row.channel_type))}</td>
      <td><span class="vendor-tag">${escapeHtml(row.vendor)}</span></td>
      <td class="mono">${escapeHtml(row.domain)}</td>
      <td>${bytesFmt(row.uplink_bytes)}</td>
      <td>${bytesFmt(row.downlink_bytes)}</td>
      <td>${bytesFmt(row.total_bytes)}</td>
      <td>${numberFmt(row.input_tokens)}</td>
      <td>${numberFmt(row.output_tokens)}</td>
      <td>${numberFmt(row.total_tokens)}</td>
      <td>${moneyFmt(estimatedCostValue(row))}</td>
      <td>${numberFmt(row.request_count)}</td>
    </tr>
  `).join('');
  renderPagination('sessionPagination', payload, 'session', page => changePage(state.selectedView, page));
}

function renderRequestLogs() {
  const root = document.getElementById('requestSection');
  root.classList.toggle('hidden', !isRequestView(state.selectedView));
  if (root.classList.contains('hidden')) return;
  document.getElementById('requestPanelTitle').textContent = detailTitle(state.selectedView);
  renderTimeRangeFilters('requestTimeFilters', 'requests', TIME_RANGE_OPTIONS_NO_ALL);
  const payload = state.requestLogsPage;
  const rows = requestRows();
  const body = document.getElementById('requestLogBody');
  document.getElementById('requestSearchMeta').textContent = `${detailMetaText(payload, state.search.requests, true)}，时间范围 ${timeRangeLabel(state.timeRanges.requests)}`;
  document.getElementById('requestLatencyHint').textContent = requestPanelHintText(state.status, state.search.requests);
  if (!rows.length) {
    body.innerHTML = '<tr><td class="empty-cell" colspan="15">当前筛选条件下暂无请求明细</td></tr>';
    renderPagination('requestPagination', payload, 'request', page => changePage(state.selectedView, page));
    return;
  }
  body.innerHTML = rows.map(row => `
    <tr>
      <td>${escapeHtml(row.iface)}</td>
      <td class="mono">${escapeHtml(row.src_ip)}</td>
      <td>${escapeHtml(row.src_user || '-')}</td>
      <td>${escapeHtml(row.seen_at || '-')}</td>
      <td>${escapeHtml(channelLabel(row.channel_type))}</td>
      <td><span class="vendor-tag">${escapeHtml(row.vendor)}</span></td>
      <td class="mono">${escapeHtml(row.domain)}</td>
      <td>${bytesFmt(row.uplink_bytes)}</td>
      <td>${bytesFmt(row.downlink_bytes)}</td>
      <td>${bytesFmt(row.total_bytes)}</td>
      <td>${numberFmt(row.input_tokens)}</td>
      <td>${numberFmt(row.output_tokens)}</td>
      <td>${numberFmt(row.total_tokens)}</td>
      <td>${moneyFmt(estimatedCostValue(row))}</td>
      <td>${numberFmt(row.request_count)}</td>
    </tr>
  `).join('');
  renderPagination('requestPagination', payload, 'request', page => changePage(state.selectedView, page));
}

function renderQuicDiagnostics() {
  const root = document.getElementById('quicSection');
  root.classList.toggle('hidden', state.selectedView !== 'quic');
  if (root.classList.contains('hidden')) return;
  renderTimeRangeFilters('quicTimeFilters', 'quic');
  const payload = state.transportEventsPage;
  const rows = quicRows();
  const body = document.getElementById('quicBody');
  document.getElementById('quicSearchMeta').textContent = `${detailMetaText(payload, state.search.quic, false)}，时间范围 ${timeRangeLabel(state.timeRanges.quic)}`;
  document.getElementById('quicHint').textContent = quicHintText(payload);
  if (!rows.length) {
    body.innerHTML = '<tr><td class="empty-cell" colspan="10">当前筛选条件下暂无 QUIC / UDP 诊断流量</td></tr>';
    renderPagination('quicPagination', payload, 'quic', page => changePage('quic', page));
    return;
  }
  body.innerHTML = rows.map(row => `
    <tr>
      <td><span class="vendor-tag">${escapeHtml(row.vendor)}</span></td>
      <td class="mono">${escapeHtml(row.domain)}</td>
      <td class="mono">${escapeHtml(row.src_ip)}</td>
      <td>${numberFmt(row.src_port)}</td>
      <td class="mono">${escapeHtml(row.dst_ip)}</td>
      <td>${numberFmt(row.dst_port)}</td>
      <td>${escapeHtml(String(row.protocol || '').toUpperCase())}</td>
      <td>${escapeHtml(channelLabel(row.channel_type))}</td>
      <td>${numberFmt(row.packet_count)}</td>
      <td>${bytesFmt(row.total_bytes)}</td>
      <td>${escapeHtml(row.first_seen || '-')}</td>
      <td>${escapeHtml(row.last_seen || '-')}</td>
    </tr>
    <tr class="detail-row">
      <td colspan="12">备注：${escapeHtml(row.note || '未识别厂商，但已确认该源 IP 存在经过当前网卡的 UDP/443 流量')}</td>
    </tr>
  `).join('');
  renderPagination('quicPagination', payload, 'quic', page => changePage('quic', page));
}

function renderInterfaceTraffic() {
  const root = document.getElementById('interfaceTrafficSection');
  root.classList.toggle('hidden', state.selectedView !== 'interfaceTraffic');
  if (root.classList.contains('hidden')) return;
  const payload = state.interfaceTraffic || emptyInterfaceTraffic();
  const rows = interfaceTrafficRows();
  const totals = payload.totals || {};
  document.getElementById('interfaceTrafficMeta').textContent = payload.available === false
    ? `接口 ${payload.iface || '-'} 暂时无法获取实时流量`
    : `接口 ${payload.iface || '-'}，最近 ${numberFmt(payload.sample_seconds || 0)} 秒窗口，Top ${numberFmt(rows.length)} 条`;
  document.getElementById('interfaceTrafficHint').textContent = interfaceTrafficHintText(payload);
  document.getElementById('interfaceTrafficTotals').innerHTML = [
    iftopSummaryCard('总发送速率', totals.send_rate),
    iftopSummaryCard('总接收速率', totals.receive_rate),
    iftopSummaryCard('总收发速率', totals.combined_rate),
    iftopSummaryCard('峰值速率', totals.peak_rate),
  ].join('');
  const body = document.getElementById('interfaceTrafficBody');
  if (!rows.length) {
    body.innerHTML = `<tr><td class="empty-cell" colspan="5">${payload.available === false ? escapeHtml(payload.message || 'iftop 采样失败') : '当前没有活跃流量'}</td></tr>`;
    return;
  }
  body.innerHTML = rows.map(row => `
    <tr>
      <td>${numberFmt(row.rank)}</td>
      <td class="mono">${escapeHtml(row.host_a)}</td>
      <td class="mono">${escapeHtml(row.host_b)}</td>
      <td>${iftopRateCell(`${escapeHtml(row.host_a)} ${escapeHtml(row.a_to_b.arrow)} ${escapeHtml(row.host_b)}`, row.a_to_b.rates)}</td>
      <td>${iftopRateCell(`${escapeHtml(row.host_a)} ${escapeHtml(row.b_to_a.arrow)} ${escapeHtml(row.host_b)}`, row.b_to_a.rates)}</td>
    </tr>
  `).join('');
}

function renderTargets() {
  const root = document.getElementById('targetSection');
  root.classList.toggle('hidden', state.selectedView !== 'targets');
  if (root.classList.contains('hidden')) return;
  const groups = state.selectedVendor === '全部'
    ? state.targets
    : state.targets.filter(item => item.vendor === state.selectedVendor);
  const host = document.getElementById('targetList');
  if (!groups.length) {
    host.innerHTML = '<div class="empty-card">当前筛选条件下暂无厂商域名规则</div>';
    return;
  }
  host.innerHTML = groups.map(item => `
    <article class="target-card">
      <div class="target-head">
        <div>
          <div class="target-vendor">${escapeHtml(item.vendor)}</div>
          <div class="target-count">${numberFmt(item.domains.length)} 条规则</div>
        </div>
      </div>
      <div class="target-domain-list">
        ${item.domains.map(domain => `
          <div class="target-domain-item">
            <div class="target-domain-main mono">${escapeHtml(domain.domain_pattern)}</div>
            <div class="target-domain-meta">
              <span class="meta-chip">${escapeHtml(labelMatchType(domain.match_type))}</span>
              <span class="meta-chip">${escapeHtml(labelSource(domain.source))}</span>
            </div>
          </div>
        `).join('')}
      </div>
    </article>
  `).join('');
}

function csvEscape(value) {
  const text = String(value == null ? '' : value);
  if (/[",\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function downloadCsv(filename, headers, rows) {
  const lines = [headers.join(',')].concat(rows.map(row => row.map(csvEscape).join(',')));
  const blob = new Blob(['\ufeff' + lines.join('\n')], {type: 'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function getExportDateRange() {
  const startEl = document.getElementById('exportStartDate');
  const endEl = document.getElementById('exportEndDate');
  const startDate = startEl && startEl.value ? localToServerDateTime(startEl.value) : '';
  const endDate = endEl && endEl.value ? localToServerDateTime(endEl.value) : '';
  return {startDate, endDate};
}

async function exportSummaryCsv() {
  const {startDate, endDate} = getExportDateRange();
  let exportRows;
  if (startDate || endDate) {
    const result = await request(`/api/summary${buildQuery({start_date: startDate, end_date: endDate})}`);
    const allRows = result.data || [];
    const vendorFiltered = filteredRows(allRows);
    exportRows = state.selectedView === 'webSummary'
      ? vendorFiltered.filter(row => row.channel_type !== 'api' && row.channel_type !== 'api_quic')
      : vendorFiltered.filter(row => row.channel_type === 'api' || row.channel_type === 'api_quic');
  } else {
    exportRows = summaryRows();
  }
  const rows = exportRows.map(row => [
    row.vendor,
    row.domain,
    channelLabel(row.channel_type),
    row.session_count,
    row.request_count,
    row.uplink_bytes,
    row.downlink_bytes,
    row.total_bytes,
    row.input_tokens,
    row.output_tokens,
    row.total_tokens,
    estimatedCostValue(row),
    row.latest_seen || '',
  ]);
  const kind = state.selectedView === 'webSummary' ? 'web_summary' : 'api_summary';
  downloadCsv(csvFilename(kind), ['模型厂商', '访问域名', '调用类型', '会话数', '请求次数', '上行流量', '下行流量', '总流量', '输入Token', '输出Token', '总Token', '预估金额USD', '最近访问时间'], rows);
  showToast(`已导出 ${rows.length} 条汇总记录`, 'success');
}

async function fetchAllPagedRows(view, pageSize, startDate, endDate) {
  let page = 1;
  let totalPages = 1;
  const items = [];
  while (page <= totalPages) {
    const config = buildViewRequest(view, {page, pageSize, startDate, endDate});
    const result = await request(config.url);
    const payload = normalizePagedPayload(result.data, page, pageSize);
    items.push.apply(items, payload.items || []);
    totalPages = Math.max(1, Number(payload.total_pages || 1));
    page += 1;
  }
  return items;
}

function buildExportQuery(exportType) {
  const {startDate, endDate} = getExportDateRange();
  const view = state.selectedView;
  const channelClass = viewChannelClass(view);
  const group = viewGroup(view);
  const hideKey = isSessionView(view) ? 'sessions' : 'requests';
  return buildQuery({
    type: exportType,
    vendor: state.selectedVendor === '全部' ? '' : state.selectedVendor,
    channel_class: channelClass,
    time_window_minutes: (startDate || endDate) ? 0 : state.timeRanges[group],
    search: state.search[group] || '',
    min_bytes: state.hideEmpty[hideKey] ? 1 : 0,
    start_date: startDate,
    end_date: endDate,
  });
}

function streamExport(exportType) {
  const qs = buildExportQuery(exportType);
  const url = `/api/export-csv${qs}`;
  showToast('正在生成导出文件，请稍候...', 'info');
  window.open(url, '_blank');
}

async function exportSessionCsv() {
  // Check total to decide streaming vs client-side
  const payload = state.logsPage;
  const total = payload ? payload.total : 0;
  if (total > STREAM_EXPORT_THRESHOLD) {
    streamExport('logs');
    return;
  }
  const {startDate, endDate} = getExportDateRange();
  const items = await fetchAllPagedRows(state.selectedView, EXPORT_PAGE_SIZE, startDate, endDate);
  const rows = items.map(row => [
    row.iface,
    row.src_ip,
    row.src_user || '',
    row.src_department || '',
    row.first_seen || '',
    row.last_seen || '',
    channelLabel(row.channel_type),
    row.vendor,
    row.domain,
    row.uplink_bytes,
    row.downlink_bytes,
    row.total_bytes,
    row.input_tokens,
    row.output_tokens,
    row.total_tokens,
    estimatedCostValue(row),
    row.request_count,
  ]);
  const kind = state.selectedView === 'webSessions' ? 'web_session_log_all' : 'api_session_log_all';
  downloadCsv(csvFilename(kind), ['抓包网卡', '源IP', '用户', '部门', '首次时间', '最近时间', '调用类型', '模型厂商', '访问域名', '上行流量', '下行流量', '总流量', '输入Token', '输出Token', '总Token', '预估金额USD', '请求次数'], rows);
  showToast(`已导出 ${rows.length} 条会话记录`, 'success');
}

async function exportRequestCsv() {
  const payload = state.requestLogsPage;
  const total = payload ? payload.total : 0;
  if (total > STREAM_EXPORT_THRESHOLD) {
    streamExport('request-logs');
    return;
  }
  const {startDate, endDate} = getExportDateRange();
  const items = await fetchAllPagedRows(state.selectedView, EXPORT_PAGE_SIZE, startDate, endDate);
  const rows = items.map(row => [
    row.iface,
    row.src_ip,
    row.src_user || '',
    row.src_department || '',
    row.seen_at || '',
    channelLabel(row.channel_type),
    row.vendor,
    row.domain,
    row.uplink_bytes,
    row.downlink_bytes,
    row.total_bytes,
    row.input_tokens,
    row.output_tokens,
    row.total_tokens,
    estimatedCostValue(row),
    row.request_count,
  ]);
  const kind = state.selectedView === 'webRequests' ? 'web_request_detail_all' : 'api_request_detail_all';
  downloadCsv(csvFilename(kind), ['抓包网卡', '源IP', '用户', '部门', '访问时间', '调用类型', '模型厂商', '访问域名', '上行流量', '下行流量', '总流量', '输入Token', '输出Token', '总Token', '预估金额USD', '请求次数'], rows);
  showToast(`已导出 ${rows.length} 条请求明细`, 'success');
}

async function exportUserSummaryCsv() {
  const {startDate, endDate} = getExportDateRange();
  const tw = (startDate || endDate) ? 0 : (state.timeRanges.userSummary || 0);
  const qs = buildQuery({
    type: 'user-summary',
    search: state.search.userSummary || '',
    time_window_minutes: tw,
    start_date: startDate,
    end_date: endDate,
  });
  const label = (startDate || endDate) ? '自定义时间' : timeRangeLabel(state.timeRanges.userSummary);
  showToast(`正在导出${label}全部用户消费数据...`, 'info');
  window.open(`/api/export-csv${qs}`, '_blank');
}

function renderUserSummary() {
  const root = document.getElementById('userSummarySection');
  root.classList.toggle('hidden', state.selectedView !== 'userSummary');
  if (root.classList.contains('hidden')) return;
  renderTimeRangeFilters('userSummaryTimeFilters', 'userSummary');
  const payload = state.userSummaryPage;
  const rows = payload.items || [];
  const body = document.getElementById('userSummaryBody');
  document.getElementById('userSummarySearchMeta').textContent = `${detailMetaText(payload, state.search.userSummary, false)}，时间范围 ${timeRangeLabel(state.timeRanges.userSummary)}`;
  if (!rows.length) {
    body.innerHTML = '<tr><td class="empty-cell" colspan="16">当前筛选条件下暂无用户消费记录</td></tr>';
    renderPagination('userSummaryPagination', payload, 'userSummary', page => changePage('userSummary', page));
    return;
  }
  body.innerHTML = rows.map(row => {
    const userDisplay = row.src_user || 'N/A';
    return `
    <tr>
      <td>${escapeHtml(userDisplay)}</td>
      <td>${escapeHtml(row.src_department || '-')}</td>
      <td class="mono">${escapeHtml(row.src_ip || '-')}</td>
      <td><span class="vendor-tag">${escapeHtml(row.vendor)}</span></td>
      <td>${escapeHtml(channelLabel(row.channel_type))}</td>
      <td class="mono">${escapeHtml(row.domain)}</td>
      <td>${numberFmt(row.request_count)}</td>
      <td>${bytesFmt(row.uplink_bytes)}</td>
      <td>${bytesFmt(row.downlink_bytes)}</td>
      <td>${bytesFmt(row.total_bytes)}</td>
      <td>${numberFmt(row.input_tokens)}</td>
      <td>${numberFmt(row.output_tokens)}</td>
      <td>${numberFmt(row.total_tokens)}</td>
      <td>${moneyFmt(estimatedCostValue(row))}</td>
      <td>${escapeHtml(row.first_seen || '-')}</td>
      <td>${escapeHtml(row.last_seen || '-')}</td>
    </tr>`;
  }).join('');
  renderPagination('userSummaryPagination', payload, 'userSummary', page => changePage('userSummary', page));
}

function exportUserTotalCsv() {
  const {startDate, endDate} = getExportDateRange();
  const tw = (startDate || endDate) ? 0 : (state.timeRanges.userTotal || 0);
  const qs = buildQuery({
    type: 'user-total',
    search: state.search.userTotal || '',
    time_window_minutes: tw,
    start_date: startDate,
    end_date: endDate,
  });
  const label = (startDate || endDate) ? '自定义时间' : timeRangeLabel(state.timeRanges.userTotal);
  showToast(`正在导出${label}用户总消费数据...`, 'info');
  window.open(`/api/export-csv${qs}`, '_blank');
}

function renderUserTotal() {
  const root = document.getElementById('userTotalSection');
  root.classList.toggle('hidden', state.selectedView !== 'userTotal');
  if (root.classList.contains('hidden')) return;
  renderTimeRangeFilters('userTotalTimeFilters', 'userTotal');
  const payload = state.userTotalPage;
  const rows = payload.items || [];
  const body = document.getElementById('userTotalBody');
  document.getElementById('userTotalSearchMeta').textContent = `${detailMetaText(payload, state.search.userTotal, false)}，时间范围 ${timeRangeLabel(state.timeRanges.userTotal)}`;
  if (!rows.length) {
    body.innerHTML = '<tr><td class="empty-cell" colspan="14">当前筛选条件下暂无用户消费记录</td></tr>';
    renderPagination('userTotalPagination', payload, 'userTotal', page => changePage('userTotal', page));
    return;
  }
  body.innerHTML = rows.map(row => {
    const userDisplay = row.src_user || 'N/A';
    return `
    <tr>
      <td>${escapeHtml(userDisplay)}</td>
      <td>${escapeHtml(row.src_department || '-')}</td>
      <td class="mono">${escapeHtml(row.src_ip || '-')}</td>
      <td>${numberFmt(row.vendor_count)}</td>
      <td>${numberFmt(row.request_count)}</td>
      <td>${bytesFmt(row.uplink_bytes)}</td>
      <td>${bytesFmt(row.downlink_bytes)}</td>
      <td>${bytesFmt(row.total_bytes)}</td>
      <td>${numberFmt(row.input_tokens)}</td>
      <td>${numberFmt(row.output_tokens)}</td>
      <td>${numberFmt(row.total_tokens)}</td>
      <td>${moneyFmt(row.estimated_cost_usd)}</td>
      <td>${escapeHtml(row.first_seen || '-')}</td>
      <td>${escapeHtml(row.last_seen || '-')}</td>
    </tr>`;
  }).join('');
  renderPagination('userTotalPagination', payload, 'userTotal', page => changePage('userTotal', page));
}

function renderAll() {
  renderSidebar();
  renderHero();
  renderPageAlert();
  renderVendorFilters();
  renderSystemMeta();
  renderSummary();
  renderUserSummary();
  renderUserTotal();
  renderSessionLogs();
  renderRequestLogs();
  renderQuicDiagnostics();
  renderInterfaceTraffic();
  renderTargets();
}

function settledRequest(label, path) {
  return request(path)
    .then(data => ({status: 'fulfilled', value: data, label}))
    .catch(error => ({status: 'rejected', reason: error, label}));
}

async function refreshCommonData() {
  const results = await Promise.all([
    settledRequest('状态', '/api/status'),
    settledRequest('汇总', '/api/summary'),
    settledRequest('厂商域名', '/api/targets'),
    settledRequest('管道', '/api/pipeline'),
  ]);

  if (results[0].status === 'fulfilled') {
    state.status = results[0].value.data;
    setLoadError('状态', false);
  } else {
    setLoadError('状态', true);
  }

  if (results[1].status === 'fulfilled') {
    state.summary = results[1].value.data;
    setLoadError('汇总', false);
  } else {
    setLoadError('汇总', true);
  }

  if (results[2].status === 'fulfilled') {
    state.targets = results[2].value.data;
    state.loadedViews.targets = true;
    setLoadError('厂商域名', false);
  } else {
    setLoadError('厂商域名', true);
  }

  if (results[3] && results[3].status === 'fulfilled') {
    state.pipeline = results[3].value.data;
  }

  state.loadedViews.common = true;
}

function buildViewRequest(view, overrides) {
  const opts = overrides || {};
  const useStartDate = opts.startDate || '';
  const useEndDate = opts.endDate || '';
  const useDateRange = !!(useStartDate || useEndDate);
  if (isSessionView(view)) {
    const group = viewGroup(view);
    const channelClass = viewChannelClass(view);
    const page = Number(opts.page || state.pagination[view] || 1);
    const pageSize = Number(opts.pageSize || SESSION_PAGE_SIZE);
    return {
      label: detailTitle(view),
      url: `/api/logs${buildQuery({
        page,
        page_size: pageSize,
        vendor: state.selectedVendor === '全部' ? '' : state.selectedVendor,
        channel_class: channelClass,
        time_window_minutes: useDateRange ? 0 : state.timeRanges[group],
        search: state.search.sessions,
        min_bytes: state.hideEmpty.sessions ? 1 : 0,
        start_date: useStartDate,
        end_date: useEndDate,
      })}`,
      page,
      pageSize,
      assign(data) {
        state.logsPage = normalizePagedPayload(data, state.pagination[view], SESSION_PAGE_SIZE);
        state.pagination[view] = state.logsPage.page;
        state.loadedViews.sessions = true;
      },
    };
  }
  if (isRequestView(view)) {
    const group = viewGroup(view);
    const channelClass = viewChannelClass(view);
    const page = Number(opts.page || state.pagination[view] || 1);
    const pageSize = Number(opts.pageSize || REQUEST_PAGE_SIZE);
    return {
      label: detailTitle(view),
      url: `/api/request-logs${buildQuery({
        page,
        page_size: pageSize,
        vendor: state.selectedVendor === '全部' ? '' : state.selectedVendor,
        channel_class: channelClass,
        time_window_minutes: useDateRange ? 0 : state.timeRanges[group],
        search: state.search.requests,
        min_bytes: state.hideEmpty.requests ? 1 : 0,
        start_date: useStartDate,
        end_date: useEndDate,
      })}`,
      page,
      pageSize,
      assign(data) {
        state.requestLogsPage = normalizePagedPayload(data, state.pagination[view], REQUEST_PAGE_SIZE);
        state.pagination[view] = state.requestLogsPage.page;
        state.loadedViews.requests = true;
      },
    };
  }
  if (view === 'quic') {
    const page = Number(opts.page || state.pagination.quic || 1);
    const pageSize = Number(opts.pageSize || QUIC_PAGE_SIZE);
    return {
      label: 'QUIC 诊断',
      url: `/api/transport-events${buildQuery({
        page,
        page_size: pageSize,
        time_window_minutes: useDateRange ? 0 : state.timeRanges.quic,
        search: state.search.quic,
        start_date: useStartDate,
        end_date: useEndDate,
      })}`,
      page,
      pageSize,
      assign(data) {
        state.transportEventsPage = normalizePagedPayload(data, state.pagination.quic, QUIC_PAGE_SIZE);
        state.pagination.quic = state.transportEventsPage.page;
        state.loadedViews.quic = true;
      },
    };
  }
  if (view === 'interfaceTraffic') {
    return {
      label: '接口流量',
      url: `/api/interface-traffic${buildQuery({
        iface: state.status && state.status.iface ? state.status.iface : '',
      })}`,
      assign(data) {
        state.interfaceTraffic = Object.assign(emptyInterfaceTraffic(), data || {});
        state.loadedViews.interfaceTraffic = true;
      },
    };
  }
  if (view === 'targets') {
    return {
      label: '厂商域名',
      url: '/api/targets',
      assign(data) {
        state.targets = data;
        state.loadedViews.targets = true;
      },
    };
  }
  if (view === 'userSummary') {
    const page = Number(opts.page || state.pagination.userSummary || 1);
    const pageSize = Number(opts.pageSize || USER_SUMMARY_PAGE_SIZE);
    return {
      label: '用户消费汇总',
      url: `/api/user-summary${buildQuery({
        page,
        page_size: pageSize,
        vendor: state.selectedVendor === '全部' ? '' : state.selectedVendor,
        search: state.search.userSummary,
        time_window_minutes: state.timeRanges.userSummary,
      })}`,
      page,
      pageSize,
      assign(data) {
        state.userSummaryPage = normalizePagedPayload(data, state.pagination.userSummary, USER_SUMMARY_PAGE_SIZE);
        state.pagination.userSummary = state.userSummaryPage.page;
        state.loadedViews.userSummary = true;
      },
    };
  }
  if (view === 'userTotal') {
    const page = Number(opts.page || state.pagination.userTotal || 1);
    const pageSize = Number(opts.pageSize || USER_SUMMARY_PAGE_SIZE);
    return {
      label: '用户总消费排行',
      url: `/api/user-total${buildQuery({
        page,
        page_size: pageSize,
        search: state.search.userTotal,
        time_window_minutes: state.timeRanges.userTotal,
      })}`,
      page,
      pageSize,
      assign(data) {
        state.userTotalPage = normalizePagedPayload(data, state.pagination.userTotal, USER_SUMMARY_PAGE_SIZE);
        state.pagination.userTotal = state.userTotalPage.page;
        state.loadedViews.userTotal = true;
      },
    };
  }
  return null;
}

async function refreshViewData(view, force) {
  if (view === 'apiSummary' || view === 'webSummary') return;
  if (isSessionView(view) && !force && state.loadedViews.sessions) return;
  if (isRequestView(view) && !force && state.loadedViews.requests) return;
  if (view === 'quic' && !force && state.loadedViews.quic) return;
  if (view === 'interfaceTraffic' && !force && state.loadedViews.interfaceTraffic) return;
  if (view === 'targets' && !force && state.loadedViews.targets) return;
  if (view === 'userSummary' && !force && state.loadedViews.userSummary) return;
  if (view === 'userTotal' && !force && state.loadedViews.userTotal) return;

  const config = buildViewRequest(view);
  if (!config) return;

  if (isSessionView(view) || isRequestView(view) || view === 'quic' || view === 'interfaceTraffic' || view === 'userSummary' || view === 'userTotal') {
    state.requestSeq[view] = (state.requestSeq[view] || 0) + 1;
  }
  const seq = state.requestSeq[view] || 0;
  const result = await settledRequest(config.label, config.url);
  if ((isSessionView(view) || isRequestView(view) || view === 'quic' || view === 'interfaceTraffic' || view === 'userSummary') && seq !== state.requestSeq[view]) {
    return;
  }

  if (result.status === 'fulfilled') {
    config.assign(result.value.data);
    setLoadError(config.label, false);
  } else {
    setLoadError(config.label, true);
  }
}

async function refreshAll(forceViewData) {
  await Promise.all([
    refreshCommonData(),
    refreshViewData(state.selectedView, Boolean(forceViewData)),
  ]);
  renderAll();
}

async function addTargetRule(event) {
  event.preventDefault();
  const vendor = document.getElementById('vendorInput').value.trim();
  const domain = document.getElementById('domainInput').value.trim();
  const matchType = document.getElementById('matchTypeInput').value;
  if (!vendor || !domain) {
    showToast('请填写厂商名称和域名规则', 'warning');
    return;
  }
  const domains = domain.split(/[\n,]+/).map(item => item.trim()).filter(Boolean);
  try {
    await request('/api/targets', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        vendor,
        domains,
        match_type: matchType,
      }),
    });
    document.getElementById('vendorInput').value = vendor;
    document.getElementById('domainInput').value = '';
    showToast(`已成功为 ${vendor} 添加 ${domains.length} 条域名规则`, 'success');
    state.selectedView = 'targets';
    state.loadedViews.targets = false;
    await refreshAll(true);
  } catch (err) {
    showToast('保存规则失败: ' + (err.message || '未知错误'), 'error');
  }
}

function changePage(view, page) {
  if (isSessionView(view) || isRequestView(view)) state.pagination[view] = Math.max(1, page);
  if (view === 'quic') state.pagination.quic = Math.max(1, page);
  if (view === 'userSummary') state.pagination.userSummary = Math.max(1, page);
  if (view === 'userTotal') state.pagination.userTotal = Math.max(1, page);
  refreshViewData(view, true).then(renderAll).catch(() => renderAll());
}

function bindSearchInput(elementId, key) {
  document.getElementById(elementId).addEventListener('input', event => {
    const value = event.target.value.trim();
    state.search[key] = value;
    if (key === 'summary') {
      renderAll();
      return;
    }
    if (key === 'sessions') {
      state.pagination.apiSessions = 1;
      state.pagination.webSessions = 1;
    }
    if (key === 'requests') {
      state.pagination.apiRequests = 1;
      state.pagination.webRequests = 1;
    }
    if (key === 'quic') state.pagination.quic = 1;
    if (key === 'userSummary') state.pagination.userSummary = 1;
    if (key === 'userTotal') state.pagination.userTotal = 1;
    renderAll();
    if (searchTimers[key]) clearTimeout(searchTimers[key]);
    searchTimers[key] = setTimeout(() => {
      if (viewGroup(state.selectedView) !== key) return;
      refreshViewData(state.selectedView, true).then(renderAll).catch(() => renderAll());
    }, SEARCH_DEBOUNCE_MS);
  });
}

document.getElementById('targetForm').addEventListener('submit', addTargetRule);
document.getElementById('exportSummaryBtn').addEventListener('click', () => {
  exportSummaryCsv()
    .then(() => {
      setLoadError('汇总导出', false);
      renderAll();
    })
    .catch(() => {
      setLoadError('汇总导出', true);
      renderAll();
    });
});
document.getElementById('exportSessionBtn').addEventListener('click', () => {
  exportSessionCsv()
    .then(() => {
      setLoadError('会话导出', false);
      renderAll();
    })
    .catch(() => {
      setLoadError('会话导出', true);
      renderAll();
    });
});
document.getElementById('exportRequestBtn').addEventListener('click', () => {
  exportRequestCsv()
    .then(() => {
      setLoadError('明细导出', false);
      renderAll();
    })
    .catch(() => {
      setLoadError('明细导出', true);
      renderAll();
    });
});
bindSearchInput('summarySearchInput', 'summary');
bindSearchInput('sessionSearchInput', 'sessions');
bindSearchInput('requestSearchInput', 'requests');
bindSearchInput('quicSearchInput', 'quic');
bindSearchInput('userSummarySearchInput', 'userSummary');
bindSearchInput('userTotalSearchInput', 'userTotal');
document.getElementById('exportUserSummaryBtn').addEventListener('click', () => {
  exportUserSummaryCsv();
});
document.getElementById('exportUserTotalBtn').addEventListener('click', () => {
  exportUserTotalCsv();
});

// Hide empty sessions toggle
function bindHideEmpty(checkboxId, group) {
  const el = document.getElementById(checkboxId);
  if (!el) return;
  el.checked = state.hideEmpty[group];
  el.addEventListener('change', function() {
    state.hideEmpty[group] = el.checked;
    refreshAll(true).catch(() => renderAll());
  });
}
bindHideEmpty('sessionHideEmpty', 'sessions');
bindHideEmpty('requestHideEmpty', 'requests');

// Export date range clear
document.getElementById('clearDateRange').addEventListener('click', () => {
  document.getElementById('exportStartDate').value = '';
  document.getElementById('exportEndDate').value = '';
  showToast('已清除自定义导出时间范围', 'info');
});

renderAll();
refreshAll().catch(() => renderAll());
setInterval(() => {
  refreshAll(true).catch(() => renderAll());
}, AUTO_REFRESH_MS);

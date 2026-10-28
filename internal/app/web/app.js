'use strict';

const $ = (id) => document.getElementById(id);
const connection = $('connection-form');
const editor = $('rule-form');
const labels = {keyword:'关键字',keyword_mapping:'关键字替换',regex:'正则表达式',private_ipv4:'私网 IPv4',block:'阻断',mask:'脱敏',warn:'告警',allow:'放行'};
let rules = [];
let editing = -1;
let dirty = false;
let busy = false;
let auditBusy = false;
let gatewayOperation = '';
let setupRequired = false;
let session = '';
let listenPrefix = '127.0.0.1:';
let auditCursors = [0];
let auditIndex = 0;
let auditNext = 0;
let auditQuery = '';
let auditLoaded = false;
let auditDetail = null;
let auditTrigger = null;
let auditRequestLoaded = false;
let auditRequestURL = '';
let liveSnapshot = null;
let liveFetching = false;
let liveRevision = 0;
let liveRowsKey = '';
try {
  const fragment = location.hash.slice(1);
  if (fragment) {
    sessionStorage.setItem('gateway-session', fragment);
    history.replaceState(null, '', location.pathname);
  }
  session = sessionStorage.getItem('gateway-session') || '';
} catch {
  session = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
}

function notice(message, error = false) {
  $('notice').hidden = !message;
  $('notice').classList.toggle('error', error);
  $('notice').textContent = message;
}

async function api(path, method = 'GET', body) {
  const options = {method, cache:'no-store', headers:{Authorization:`Bearer ${session}`}};
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  const response = await fetch(`/api/${path}`, options);
  const raw = await response.text();
  let data;
  try { data = JSON.parse(raw); } catch { throw new Error(raw || '管理服务未返回有效内容'); }
  if (!response.ok) throw new Error(data.error || '操作失败');
  return data;
}

async function action(work) {
  if (busy || gatewayOperation) return;
  busy = true;
  updateActionButtons();
  try { await work(); }
  catch (error) { notice(error.message, true); }
  finally {
    busy = false;
    updateActionButtons();
    await refreshStatus();
  }
}

function updateActionButtons() {
  document.querySelectorAll('button').forEach(button => {
    button.disabled = button.matches('[data-tab], #audit-close') ? false
      : button.closest('#audits, #audit-detail') ? auditBusy : busy || !!gatewayOperation;
  });
  $('start-gateway').disabled = busy || !!gatewayOperation || setupRequired;
  updateAuditPagination();
  updateLiveControls();
}

// 审计查询独立于保存与启停，等待代理结束在途请求时仍可查看原因。
async function auditAction(work) {
  if (auditBusy) return;
  auditBusy = true;
  updateActionButtons();
  try { await work(); }
  catch (error) { notice(error.message, true); }
  finally { auditBusy = false; updateActionButtons(); }
}

function httpWarning() {
  $('http-warning').hidden = !connection.elements.upstream.value.trim().toLowerCase().startsWith('http:');
}

function updateAuthMode() {
  const clientAuth = connection.elements.auth_mode.value === 'client';
  $('upstream-key-field').hidden = clientAuth;
  connection.elements.upstream_key.disabled = clientAuth;
  $('auth-hint').textContent = clientAuth ? '客户端继续使用现有认证配置，网关将认证信息转发到固定上游。保存后会清除网关之前保存的上游 Key。' : '客户端使用网关生成的本地令牌，网关替换为此处保存的上游密钥。';
}

async function loadConnection() {
  const data = await api('settings');
  const values = data.settings;
  const clientAuth = values.auth_mode === 'client';
  connection.elements.auth_mode.value = clientAuth ? 'client' : 'gateway';
  updateAuthMode();
  for (const key of ['upstream','max_concurrent_requests','audit_retention_days']) connection.elements[key].value = values[key];
  if (values.setup_required) connection.elements.upstream.value = '';
  const separator = values.listen.lastIndexOf(':');
  listenPrefix = values.listen.slice(0,separator+1);
  connection.elements.listen_port.value = values.listen.slice(separator+1);
  $('listen-hint').textContent = `仅监听本机 ${listenPrefix.slice(0,-1)}，端口范围 1 至 65535，默认 18080。`;
  connection.elements.body_mib.value = values.max_body_bytes / 1048576;
  connection.elements.audit_mib.value = values.audit_max_bytes / 1048576;
  connection.elements.upstream_key.value = '';
  connection.elements.upstream_key.placeholder = data.key_configured ? '已保存密钥；留空表示保留原值' : '填写上游 API Key';
  $('key-state').textContent = data.key_configured ? '已保存。密钥使用系统加密保护，不会回显。' : '尚未配置上游密钥，代理暂未启动。';
  $('client-base').textContent = `http://${values.listen}/v1`;
  $('copy-token').hidden = clientAuth;
  $('client-auth').textContent = clientAuth ? '继续使用客户端现有的认证密钥。' : '认证密钥使用本地令牌。';
  $('client-auth-detail').textContent = clientAuth ? '网关不读取客户端认证文件，不保存请求中的认证密钥；上游负责验证凭证。' : '本地令牌由程序自动生成；上游 API Key 仅由网关持有。';
  httpWarning();
}

async function refreshStatus() {
  try {
    const data = await api('status');
    const ok = data.running && data.healthy;
    gatewayOperation = data.operation || '';
    setupRequired = data.setup_required;
    const operationLabel = {restarting:'正在重启代理',stopping:'正在停止代理',saving_settings:'正在保存设置并重启代理',saving_rules:'正在保存并应用规则'}[gatewayOperation];
    $('status').textContent = operationLabel ? `○ ${operationLabel}` : data.setup_required ? '○ 待配置上游' : ok ? '● 本地代理运行中' : data.running ? '● 审计不可用' : '○ 代理已停止';
    $('status').className = operationLabel ? '' : ok ? 'ok' : 'bad';
    $('setup-state').hidden = !data.setup_required;
    updateActionButtons();
    $('runtime-state').textContent = operationLabel || (data.setup_required ? '待配置上游' : data.running ? '本地运行中（不代表上游可用）' : '已停止');
    $('audit-state').textContent = !data.running ? operationLabel ? '代理切换中' : '未运行' : data.healthy ? '正常' : '不可用，已拒绝新请求';
    $('rule-version').textContent = data.rule_version || '—';
    $('app-version').textContent = data.version;
    $('data-directory').textContent = data.data_directory;
    $('runtime-error').textContent = [data.error, data.payload_error && `最近一次载荷拒绝：${data.payload_error}`].filter(Boolean).join('；') || '无';
  } catch {
    $('status').textContent = '○ 管理服务已断开';
    $('status').className = 'bad';
  }
}

function resetUpstreamCheck() {
  $('upstream-check-result').className = '';
  $('upstream-check-result').textContent = '检查当前地址下的 /models 路径，无需保存；不携带认证，不调用模型。';
}

async function checkUpstream() {
  const address = connection.elements.upstream.value.trim();
  if (!address) throw new Error('请先填写实际使用的上游 API 地址。');
  const output = $('upstream-check-result');
  output.className = '';
  output.textContent = '正在检查上游连接，最多等待 5 秒…';
  try {
    const result = await api('check-upstream', 'POST', {upstream:address});
    // 用户在检查期间改了地址时，不将旧地址的检查结果显示到新地址上。
    if (connection.elements.upstream.value.trim() !== address) return;
    if (result.reachable) {
      const hints = {
        401:'本次检查未携带认证，检查路径返回需要认证；客户端仍可沿用原有密钥。',
        403:'检查路径拒绝访问，请结合上游访问限制和客户端实际调用判断。',
        404:'检查路径 /models 返回 404，可能未开放该路径；不代表 Responses 或 Chat Completions 接口不可用。',
        405:'检查路径不接受 HEAD 方法；不代表客户端的 POST 请求不可用。'
      };
      const hint = hints[result.http_status] || (result.http_status >= 500 ? '上游返回服务端错误，请结合客户端实际调用排查。' : result.http_status >= 300 && result.http_status < 400 ? '检查路径返回重定向，本次检查未跟随跳转。' : '');
      output.className = result.http_status >= 300 ? 'check-warning' : 'check-success';
      output.textContent = `网络可达 · HTTP ${result.http_status} · ${result.duration_ms} ms。${hint}${result.message}`;
    } else {
      output.className = 'danger';
      output.textContent = `连接检查失败：${result.message}。`;
    }
  } catch (error) {
    if (connection.elements.upstream.value.trim() === address) {
      output.className = 'danger';
      output.textContent = error.message;
    }
    throw error;
  }
}

function markDirty() {
  dirty = true;
  $('rules-state').textContent = '有未保存的修改';
}

function cell(row, text, className) {
  const item = document.createElement('td');
  item.textContent = text;
  if (className) item.className = className;
  row.append(item);
  return item;
}

const auditResults = {blocked:'规则阻断',rejected:'系统拒绝',forwarding:'已转发，等待完成',completed:'已完成',upstream_error:'上游请求失败',upstream_http_error:'上游返回错误',upstream_stream_error:'响应流中断',client_canceled:'请求已取消或客户端已断开'};
const upstreamFailureReasons = {
  upstream_dns_error:'上游域名解析失败',upstream_connection_refused:'上游拒绝连接',
  upstream_tls_error:'TLS 握手或证书校验失败',upstream_timeout:'上游请求超时',
  client_canceled:'请求已取消或客户端已断开连接'
};
const auditErrors = {
  unsupported_payload:'请求结构不受支持，未进入内容规则检测。',
  gateway_unauthorized:'请求认证缺失或无效。',gateway_route_not_supported:'接口路径、方法或协议不受支持。',
  gateway_busy:'并发请求超过限制。',payload_too_large:'请求体超过大小限制。',
  unsupported_media_type:'请求格式或压缩格式不受支持。',security_engine_unavailable:'安全检测服务异常。',
  upstream_error:'原因未细分：连接上游失败、超时或响应传输中断。',
  upstream_http_error:'上游返回错误状态码，错误响应已转发。',
  ...upstreamFailureReasons
};
function auditResult(item) {
  const result = auditResults[item.result] || item.result;
  if (['upstream_error','upstream_stream_error'].includes(item.result) && upstreamFailureReasons[item.error_code]) return `${result} · ${upstreamFailureReasons[item.error_code]}`;
  return item.result === 'upstream_http_error' && item.upstream_status != null ? `${result} · HTTP ${item.upstream_status}` : result;
}
function auditTime(value) { return new Date(value).toLocaleString('zh-CN', {hour12:false}); }
function updateAuditPagination() {
  $('audit-prev').disabled = auditBusy || auditIndex === 0;
  $('audit-next').disabled = auditBusy || !auditNext;
}
async function searchAudits() {
  const form = $('audit-filter').elements;
  const query = new URLSearchParams();
  for (const key of ['action','request_id','rule_name']) if (form[key].value.trim()) query.set(key, form[key].value.trim());
  for (const key of ['since','until']) if (form[key].value) query.set(key, new Date(form[key].value).toISOString());
  await loadAudits(0, query.toString());
  auditCursors = [0]; auditIndex = 0;
}
async function loadAudits(before, query = auditQuery) {
  const params = new URLSearchParams(query);
  if (before) params.set('before', before);
  const data = await api(`audits?${params}`);
  auditQuery = query; auditNext = data.next_before; auditLoaded = true;
  resetAuditRequest();
  $('audit-detail').close();
  const tbody = $('audit-body');
  tbody.replaceChildren();
  for (const item of data.items) {
    const row = document.createElement('tr');
    cell(row, auditTime(item.occurred_at));
    const request = cell(row, item.request_id, 'audit-request'); request.title = item.request_id;
    cell(row, labels[item.action] || item.action, item.action === 'block' ? 'danger' : '');
    const result = item.error_code ? `${auditResult(item)} · ${item.error_code}` : auditResult(item);
    cell(row, result, item.error_code ? 'danger' : ''); cell(row, item.match_count);
    const button = document.createElement('button'); button.type = 'button'; button.textContent = '查看详情';
    button.addEventListener('click', () => auditAction(() => showAuditDetail(item.id, button)));
    cell(row, '').append(button); tbody.append(row);
  }
  if (!data.items.length) {
    const row = document.createElement('tr'); cell(row, '没有符合条件的记录。').colSpan = 6; tbody.append(row);
  }
  $('audit-page').textContent = `本页 ${data.items.length} 条 · 每页最多 50 条`;
  notice('');
}
async function showAuditDetail(id, trigger) {
  const item = await api(`audits/${id}`);
  resetAuditRequest();
  auditDetail = item;
  $('audit-request').hidden = item.event_type !== 'decision' || item.action !== 'block';
  const matches = item.matches || [];
  const blockers = [...new Set(matches.filter(hit => hit.action === 'block').map(hit => hit.rule_name || hit.rule_id))];
  const unknown = matches.some(hit => !['block','mask','warn','allow'].includes(hit.action));
  const verdict = $('audit-verdict');
  verdict.className = `audit-verdict ${item.action === 'block' ? 'blocked' : 'passed'}`;
  verdict.textContent = item.event_type === 'system_error' ? `系统拒绝：${auditErrors[item.error_code] || item.error_code || '请查看错误代码。'}`
    : item.action === 'block' ? blockers.length ? `阻断规则：${blockers.join('、')}。请求未发送上游。${unknown ? '部分命中未记录逐条动作，无法确认是否还有其他阻断规则。' : ''}`
      : '该请求已被阻断，但历史记录未保存逐条动作，无法可靠确定具体阻断规则。请使用新版重新测试。'
    : `已通过内容规则检查${item.action === 'mask' ? '，执行替换后转发' : ''}；请求是否完成请查看处理结果。`;
  const summary = $('audit-summary'); summary.replaceChildren();
  for (const [label,value] of [
    ['请求 ID',item.request_id],['发生时间',auditTime(item.occurred_at)],['用户',item.user],
    ['处置动作',labels[item.action] || item.action],['处理结果',auditResult(item)],
    ['规则版本',item.rule_set_version],['命中次数',item.match_count],['上游状态码',item.upstream_status ?? '未收到上游响应'],
    ['处理耗时',`${item.duration_ms} ms`],['失败原因',auditErrors[item.error_code] || item.error_code || '无'],['错误代码',item.error_code || '无']
  ]) {
    const pair = document.createElement('div'); const term = document.createElement('dt'); const definition = document.createElement('dd');
    term.textContent = label; definition.textContent = value; pair.append(term, definition); summary.append(pair);
  }
  const hits = $('audit-hits'); hits.replaceChildren();
  const priority = {block:0,mask:1,warn:2,allow:3};
  for (const hit of [...matches].sort((a,b) => (priority[a.action] ?? 4) - (priority[b.action] ?? 4))) {
    const row = document.createElement('tr');
    if (hit.action === 'block') row.className = 'audit-blocking-hit';
    const name = cell(row, hit.rule_name || hit.rule_id, 'audit-hit'); name.title = hit.rule_id;
    cell(row, labels[hit.type] || hit.type);
    const outcome = cell(row, '');
    const badge = document.createElement('span');
    badge.className = `hit-outcome hit-${['block','mask','warn','allow'].includes(hit.action) ? hit.action : 'unknown'}`;
    badge.textContent = {block:'导致阻断',mask:item.action === 'block' ? '替换预检' : '执行替换',warn:'仅告警',allow:'放行'}[hit.action] || '未记录';
    outcome.append(badge);
    if (hit.action === 'block') {
      const reason = document.createElement('small');
      reason.textContent = hit.reason === 'unsafe_mask' ? '此位置不可安全替换，转为阻断' : '命中拦截规则';
      outcome.append(reason);
    }
    cell(row, hit.keyword || '此类规则不保存原始命中文本', 'audit-hit'); hits.append(row);
  }
  $('audit-reason').textContent = '红色行是阻断原因，优先展示。替换预检表示该命中可替换，告警本身不阻断；判定取自请求发生时的记录。未记录逐条动作的旧日志无法还原判定。';
  if (!item.matches?.length) {
    const row = document.createElement('tr'); cell(row, item.event_type === 'system_error' ? '系统拒绝，没有内容规则命中记录。' : '本次请求未命中规则。').colSpan = 4; hits.append(row);
  }
  auditTrigger = trigger;
  $('audit-detail').showModal();
  $('audit-detail').querySelector('.audit-dialog-content').scrollTop = 0;
}

function resetAuditRequest() {
  if (auditRequestURL) URL.revokeObjectURL(auditRequestURL);
  auditRequestURL = ''; auditRequestLoaded = false; auditDetail = null;
  $('audit-request').hidden = true;
  $('audit-request-content').hidden = true;
  $('audit-request-body').replaceChildren();
  $('audit-request-body').hidden = false;
  $('audit-request-state').textContent = '';
  $('show-audit-request').textContent = '展开请求内容';
  $('show-audit-request').setAttribute('aria-expanded','false');
  $('download-audit-request').hidden = true;
  $('download-audit-request').removeAttribute('href');
}

// 只格式化 JSON 标点和字符串，保留数字的原始精度。
function formatAuditRequest(raw) {
  let depth = 0;
  return raw.replace(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\],:]|\s+/g, token => {
    if (token.startsWith('"')) return JSON.stringify(JSON.parse(token));
    if (token === '{' || token === '[') return `${token}\n${'  '.repeat(++depth)}`;
    if (token === '}' || token === ']') return `\n${'  '.repeat(--depth)}${token}`;
    if (token === ',') return `,\n${'  '.repeat(depth)}`;
    if (token === ':') return ': ';
    return '';
  });
}

function renderAuditRequest(raw) {
  const maxChars = 300000, maxHighlights = 2000, maxKeywords = 200;
  const truncated = raw.length > maxChars;
  const text = truncated ? raw.slice(0,maxChars) : formatAuditRequest(raw).slice(0,maxChars);
  const keywords = [...new Set((auditDetail.matches || []).map(hit => hit.keyword).filter(Boolean))];
  const patterns = new Set();
  for (const keyword of keywords.slice(0,maxKeywords)) {
    const escaped = JSON.stringify(keyword).slice(1,-1);
    patterns.add(escaped);
    patterns.add(escaped.replace(/[<>&\u2028\u2029]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4,'0')}`));
  }
  const ranges = [];
  for (const pattern of patterns) {
    let offset = 0;
    while (ranges.length < maxHighlights) {
      const start = text.indexOf(pattern,offset);
      if (start < 0) break;
      ranges.push([start,start+pattern.length]); offset = start+pattern.length;
    }
    if (ranges.length >= maxHighlights) break;
  }
  ranges.sort((a,b) => a[0]-b[0] || b[1]-a[1]);
  const merged = [];
  for (const range of ranges) {
    const previous = merged[merged.length-1];
    if (previous && range[0] < previous[1]) previous[1] = Math.max(previous[1],range[1]);
    else merged.push([...range]);
  }
  const fragment = document.createDocumentFragment();
  let offset = 0;
  for (const [start,end] of merged) {
    fragment.append(document.createTextNode(text.slice(offset,start)));
    const mark = document.createElement('mark'); mark.textContent = text.slice(start,end); fragment.append(mark);
    offset = end;
  }
  fragment.append(document.createTextNode(text.slice(offset)));
  $('audit-request-body').replaceChildren(fragment);
  const notes = [`已高亮 ${merged.length} 处命中词出现位置。`];
  if (truncated || text.length === maxChars) notes.push('内容较长，当前预览前 30 万字符，可下载完整 JSON。');
  if (keywords.length > maxKeywords || ranges.length >= maxHighlights) notes.push('命中较多，仅高亮前 200 个命中词、最多 2000 处位置。');
  if (!merged.length) notes.push('未在预览原文中找到可高亮的已保存命中词，请结合上方规则明细查看。');
  $('audit-request-state').textContent = notes.join('');
}

$('show-audit-request').addEventListener('click', () => auditAction(async () => {
  if (!auditDetail) return;
  const content = $('audit-request-content');
  if (!content.hidden && auditRequestLoaded) {
    content.hidden = true; $('show-audit-request').textContent = '展开请求内容';
    $('show-audit-request').setAttribute('aria-expanded','false'); return;
  }
  if (!auditRequestLoaded) {
    const detail = auditDetail;
    let data;
    try { data = await api(`audits/${detail.id}/request`); }
    catch (error) {
      if (auditDetail === detail) {
        $('audit-request-state').textContent = `请求内容加载失败：${error.message}，请重试。`;
        content.hidden = false;
        $('show-audit-request').textContent = '重新加载请求内容';
        $('show-audit-request').setAttribute('aria-expanded','true');
      }
      return;
    }
    if (auditDetail !== detail) return;
    if (data.request_body) {
      renderAuditRequest(data.request_body);
      auditRequestURL = URL.createObjectURL(new Blob([data.request_body],{type:'application/json;charset=utf-8'}));
      const download = $('download-audit-request');
      download.href = auditRequestURL; download.download = `blocked-request-${auditDetail.id}.json`; download.hidden = false;
    } else {
      $('audit-request-body').hidden = true;
      $('audit-request-state').textContent = '该历史记录未保存请求内容，无法还原。';
    }
    auditRequestLoaded = true;
  }
  content.hidden = false; $('show-audit-request').textContent = '收起请求内容';
  $('show-audit-request').setAttribute('aria-expanded','true');
}));

$('audit-filter').addEventListener('submit', event => { event.preventDefault(); auditAction(searchAudits); });
$('audit-reset').addEventListener('click', () => { $('audit-filter').reset(); auditAction(searchAudits); });
$('audit-next').addEventListener('click', () => auditAction(async () => {
  const cursor = auditNext;
  await loadAudits(cursor);
  auditCursors = auditCursors.slice(0, auditIndex + 1); auditCursors.push(cursor); auditIndex++;
}));
$('audit-prev').addEventListener('click', () => auditAction(async () => { await loadAudits(auditCursors[auditIndex-1]); auditIndex--; }));
$('audit-close').addEventListener('click', () => $('audit-detail').close());
$('audit-detail').addEventListener('close', () => {
  resetAuditRequest();
  auditTrigger?.focus({preventScroll:true});
  auditTrigger = null;
});

const livePhases = {received:'已接收',reading:'读取请求中',inspecting:'内容检查中',forwarding:'等待上游响应',responding:'接收响应中',completed:'已完成',blocked:'规则阻断',rejected:'本地拒绝',failed:'请求失败',interrupted:'客户端已断开',capture_stopped:'采集已停止'};
function updateLiveControls() {
  $('live-toggle').disabled = busy || !!gatewayOperation || !liveSnapshot;
  $('live-clear').disabled = busy || !!gatewayOperation || !liveSnapshot?.items.length;
}
function renderLiveRows() {
  if (!liveSnapshot) return;
  const search = $('live-search').value.trim().toLowerCase();
  const onlyErrors = $('live-errors').checked;
  const items = liveSnapshot.items.filter(item => {
    const abnormal = item.status >= 400 || item.upstream_status >= 400 || item.error_code || item.audit_error;
    return (!onlyErrors || abnormal) && (!search || [item.request_id,item.method,item.path,item.error_code,...(item.rule_names || []),...(item.rule_ids || [])].join(' ').toLowerCase().includes(search));
  });
  const key = JSON.stringify([items,liveSnapshot.enabled,search,onlyErrors]);
  if (key === liveRowsKey) return;
  liveRowsKey = key;
  const tbody = $('live-body'); tbody.replaceChildren();
  for (const item of items) {
    const row = document.createElement('tr');
    cell(row, auditTime(item.received_at));
    const request = cell(row, item.request_id, 'audit-request'); request.title = item.request_id;
    cell(row, `${item.method} ${item.path}`, 'live-path');
    cell(row, livePhases[item.phase] || item.phase, item.error_code || item.status >= 400 || item.upstream_status >= 400 ? 'danger' : '');
    cell(row, item.status || '—'); cell(row, item.upstream_status || '—');
    cell(row, `${item.duration_ms} ms`);
    cell(row, labels[item.action] || '—');
    const details = [];
    if (item.error_code) details.push(auditErrors[item.error_code] || item.error_code);
    if (item.detail) details.push(item.detail);
    if (item.upstream_status) details.push(`${item.streaming ? 'SSE；' : ''}收到上游响应头 ${item.header_ms} ms`);
    if (item.audit_error) details.push('审计写入失败，请检查运行状态');
    const names = item.rule_names?.length ? item.rule_names : item.rule_ids;
    if (names?.length) details.push(`命中：${names.join('、')}`);
    cell(row, details.join('；') || '—', 'live-detail');
    tbody.append(row);
  }
  if (!items.length) {
    const row = document.createElement('tr');
    cell(row, liveSnapshot.items.length ? '没有符合筛选条件的请求。' : liveSnapshot.enabled ? '采集中，等待新请求进入网关…' : '采集已关闭。开启后显示新进入网关的请求。').colSpan = 9;
    tbody.append(row);
  }
}
function renderLiveLogs(data) {
  liveSnapshot = data;
  $('live-toggle').textContent = data.enabled ? '关闭采集' : '开启采集';
  $('live-state').textContent = `${data.enabled ? '采集中 · 每秒刷新' : '采集已关闭'} · 已保留 ${data.items.length} / ${data.capacity} 条${data.dropped ? ` · 已淘汰 ${data.dropped} 条较早请求` : ''}`;
  $('live-error').hidden = true;
  updateLiveControls(); renderLiveRows();
}
async function refreshLiveLogs() {
  if (liveFetching) return;
  liveFetching = true;
  const revision = liveRevision;
  try {
    const data = await api('live-logs');
    if (revision === liveRevision) renderLiveLogs(data);
  } catch (error) {
    if (revision === liveRevision) {
      $('live-error').textContent = `实时日志连接中断：${error.message}。正在重试，列表可能已过期。`;
      $('live-error').hidden = false;
    }
  } finally { liveFetching = false; }
}
$('live-toggle').addEventListener('click', () => action(async () => {
  liveRevision++;
  renderLiveLogs(await api('live-logs','PUT',{enabled:!liveSnapshot.enabled}));
}));
$('live-clear').addEventListener('click', () => action(async () => {
  liveRevision++;
  renderLiveLogs(await api('live-logs','DELETE'));
}));
$('live-search').addEventListener('input', renderLiveRows);
$('live-errors').addEventListener('change', renderLiveRows);

function renderRules() {
  const tbody = $('rules-body');
  tbody.replaceChildren();
  rules.forEach((rule, index) => {
    const row = document.createElement('tr');
    const enabled = document.createElement('input');
    enabled.type = 'checkbox';
    enabled.checked = rule.enabled;
    enabled.setAttribute('aria-label', `启用规则 ${rule.name || rule.id}`);
    enabled.addEventListener('change', () => { rule.enabled = enabled.checked; markDirty(); });
    cell(row, '').append(enabled);
    const name = cell(row, rule.name || rule.id, 'audit-hit'); name.title = rule.id || '';
    cell(row, labels[rule.type]);
    cell(row, labels[rule.action], rule.action === 'block' ? 'danger' : '');
    const preview = rule.type === 'keyword' ? (rule.keywords || []).join('、') : rule.type === 'keyword_mapping' ? (rule.mappings || []).map(item => `${item.source} → ${item.target}`).join('；') : rule.type === 'regex' ? rule.pattern : '10/8、172.16/12、192.168/16';
    const summary = cell(row, preview, 'preview');
    summary.title = preview;
    const commands = cell(row, '');
    const edit = document.createElement('button');
    edit.textContent = '编辑';
    edit.addEventListener('click', () => openEditor(index));
    const remove = document.createElement('button');
    remove.textContent = '删除';
    remove.className = 'danger';
    remove.addEventListener('click', () => {
      if (!confirm(`删除规则“${rule.name || rule.id}”？保存并应用后生效。`)) return;
      rules.splice(index, 1); markDirty(); renderRules();
    });
    commands.append(edit, remove);
    tbody.append(row);
  });
  if (!rules.length) {
    const row = document.createElement('tr');
    const empty = cell(row, '暂无规则。保存空规则集后，所有可检查请求将默认放行。');
    empty.colSpan = 6;
    tbody.append(row);
  }
}

async function loadRules() {
  const data = await api('rules');
  rules = data.rules || [];
  dirty = false;
  $('rules-state').textContent = `已保存版本 ${data.version} · ${rules.length} 条规则`;
  renderRules();
}

function updateEditor() {
  const type = editor.elements.type.value;
  const actionSelect = editor.elements.action;
  for (const option of actionSelect.options) option.disabled = type === 'keyword_mapping' ? option.value !== 'mask' : type === 'keyword' || type === 'private_ipv4' ? option.value === 'mask' : false;
  if (type === 'keyword_mapping') actionSelect.value = 'mask';
  else if (actionSelect.selectedOptions[0].disabled) actionSelect.value = 'block';
  $('values-label').hidden = type === 'private_ipv4';
  editor.elements.values.required = type !== 'private_ipv4';
  $('values-title').textContent = type === 'regex' ? '正则表达式' : type === 'keyword_mapping' ? '替换映射（每行一组：源关键字=目标字）' : '关键字（每行一个）';
  $('replacement-label').hidden = type !== 'regex' || actionSelect.value !== 'mask';
  editor.elements.replacement.required = !$('replacement-label').hidden;
}

function openEditor(index) {
  if (busy) return;
  editing = index;
  editor.reset();
  $('rule-error').hidden = true;
  $('rule-title').textContent = index < 0 ? '新增规则' : '编辑规则';
  if (index >= 0) {
    const rule = rules[index];
    for (const key of ['type','action']) editor.elements[key].value = rule[key];
    editor.elements.name.value = rule.name || rule.id;
    editor.elements.case_sensitive.checked = rule.case_sensitive;
    editor.elements.enabled.checked = rule.enabled;
    editor.elements.values.value = rule.type === 'keyword' ? (rule.keywords || []).join('\n') : rule.type === 'keyword_mapping' ? (rule.mappings || []).map(item => `${item.source}=${item.target}`).join('\n') : rule.pattern || '';
    editor.elements.replacement.value = rule.replacement || '';
  }
  updateEditor();
  $('rule-dialog').showModal();
}

document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab === button));
  for (const name of ['connection','rules','audits','live','runtime']) $(name).hidden = name !== button.dataset.tab;
  if (button.dataset.tab === 'audits' && !auditLoaded) auditAction(searchAudits);
  if (button.dataset.tab === 'live') refreshLiveLogs();
}));
connection.elements.upstream.addEventListener('input', () => { httpWarning(); resetUpstreamCheck(); });
$('check-upstream').addEventListener('click', () => action(checkUpstream));
connection.elements.auth_mode.addEventListener('change', updateAuthMode);
connection.addEventListener('submit', event => {
  event.preventDefault();
  action(async () => {
    const form = connection.elements;
    const port = Number(form.listen_port.value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('本地监听端口必须是 1 至 65535 的整数。');
    if (port === Number(location.port)) throw new Error('该端口正用于 Web 管理页，请选择其他本地监听端口。');
    const result = await api('settings', 'PUT', {auth_mode:form.auth_mode.value,listen:`${listenPrefix}${port}`,upstream:form.upstream.value.trim(),upstream_key:form.auth_mode.value === 'client' ? '' : form.upstream_key.value,
      max_body_bytes:Math.round(Number(form.body_mib.value)*1048576),max_concurrent_requests:Number(form.max_concurrent_requests.value),
      audit_retention_days:Number(form.audit_retention_days.value),audit_max_bytes:Math.round(Number(form.audit_mib.value)*1048576)});
    await loadConnection();
    notice(result.error ? `设置已保存，代理未启动：${result.error}` : '设置已保存并生效。', !!result.error);
  });
});
$('copy-token').addEventListener('click', () => action(async () => {
  const data = await api('token', 'POST');
  try { await navigator.clipboard.writeText(data.token); notice('本地令牌已复制，可用于客户端认证。'); }
  catch { prompt('请复制本地令牌，不要分享给其他用户：', data.token); }
}));
$('add-rule').addEventListener('click', () => openEditor(-1));
$('cancel-rule').addEventListener('click', () => $('rule-dialog').close());
editor.elements.type.addEventListener('change', updateEditor);
editor.elements.action.addEventListener('change', updateEditor);
editor.addEventListener('submit', event => {
  event.preventDefault();
  try {
    const form = editor.elements;
    const rule = {id:editing < 0 ? '' : rules[editing].id,name:form.name.value.trim(),type:form.type.value,action:form.action.value,enabled:form.enabled.checked,case_sensitive:form.case_sensitive.checked};
    if (!rule.name || Array.from(rule.name).length > 128 || /[\u0000-\u001f\u007f-\u009f]/.test(rule.name)) throw new Error('请填写 1 至 128 个字符的规则名称，不能包含控制字符。');
    const lines = form.values.value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    if (rule.type === 'keyword') rule.keywords = lines;
    if (rule.type === 'keyword_mapping') rule.mappings = lines.map(line => {
      const separator = line.indexOf('=');
      if (separator <= 0 || separator === line.length-1) throw new Error('替换映射应为“源关键字=目标字”，两边均不能为空。');
      return {source:line.slice(0,separator),target:line.slice(separator+1)};
    });
    if (rule.type === 'regex') { rule.pattern = form.values.value; if (rule.action === 'mask') rule.replacement = form.replacement.value; }
    if (editing < 0) rules.push(rule); else rules[editing] = rule;
    markDirty(); renderRules(); $('rule-dialog').close();
  } catch (error) { $('rule-error').textContent = error.message; $('rule-error').hidden = false; }
});
$('save-rules').addEventListener('click', () => action(async () => {
  if (!rules.length && !confirm('确定保存空规则集？所有可检查请求将默认放行。')) return;
  const result = await api('rules','PUT',{rules});
  await loadRules();
  notice(result.error ? `规则已保存：${result.error}` : '规则已保存并应用；停止中的代理会在下次启动时加载。', !!result.error);
}));
for (const [button,endpoint] of [['start-gateway','start'],['stop-gateway','stop']]) $(button).addEventListener('click', () => action(async () => {
  const result = await api(endpoint,'POST');
  notice(result.error || (endpoint === 'start' ? '代理已启动。' : '代理已停止，管理页面仍可使用。'),!!result.error);
}));
window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
action(async () => { await loadConnection(); await loadRules(); await refreshStatus(); });
setInterval(() => { if (!document.hidden) refreshStatus(); },5000);
setInterval(() => { if (!$('live').hidden && !document.hidden) refreshLiveLogs(); },1000);

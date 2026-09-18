'use strict';

(() => {
  const app = document.getElementById('app');
  const dialog = document.getElementById('editor');
  const notifications = document.getElementById('notifications');
  const state = {admin: null, csrf: '', page: 'dashboard', render: 0, main: null, title: null};
  const sections = [
    ['dashboard', 'Overview', '◫', 'Workspace'], ['engines', 'Engines', '▣'],
    ['upstream-models', 'Discovery', '⌕'], ['models', 'Models', '◇'], ['keys', 'API keys', '⚿'],
    ['statistics', 'Statistics', '▤', 'Activity'], ['access-logs', 'Access logs', '≡'], ['audit-logs', 'Audit logs', '☷'],
    ['backups', 'Backups', '▥', 'Administration'], ['admins', 'Administrators', '♙'], ['settings', 'Settings', '⚙']
  ];
  const capabilityNames = {
    models: 'Model listing', chat_completions: 'Chat completions', responses: 'Responses',
    completions: 'Text completions', embeddings: 'Embeddings', rerank: 'Reranking',
    messages: 'Anthropic messages', streaming: 'Streaming', tools: 'Tool calling', vision: 'Vision'
  };
  const descriptions = {
    dashboard: 'Your engines, published models, and gateway activity at a glance.',
    engines: 'Connect local inference servers and monitor their availability.',
    'upstream-models': 'Discover models from your engines, then choose which ones to publish.',
    models: 'Give upstream models stable aliases and control who can use them.',
    keys: 'Create client credentials, organize them with tags, and manage model access.',
    statistics: 'Explore request volume, token usage, and performance over time.',
    'access-logs': 'Inspect request metadata, timings, and errors. Times display in your local timezone.',
    'audit-logs': 'Review administrative changes and security events.',
    backups: 'Create snapshots and stage a verified restore for the next gateway restart.',
    admins: 'Manage the people who can configure this gateway.',
    settings: 'Configure the listener, health checks, logging, and data retention.'
  };

  function node(tag, attributes = {}, ...children) {
    const element = document.createElement(tag);
    for (const [key, value] of Object.entries(attributes)) {
      if (value === undefined || value === null) continue;
      if (key === 'text') element.textContent = String(value);
      else if (key === 'class') element.className = value;
      else if (['checked', 'disabled', 'required', 'readOnly', 'hidden', 'multiple'].includes(key)) element[key] = Boolean(value);
      else element.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child !== null && child !== undefined) element.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return element;
  }
  function button(label, handler, className = '', attributes = {}) {
    const element = node('button', {type: 'button', class: `button ${className}`, ...attributes}, label);
    if (handler) element.addEventListener('click', () => run(() => handler(element)));
    return element;
  }
  function link(label, href, className = '') {return node('a', {href, class: className}, label);}
  function num(value, maximumFractionDigits = 0) {return Number(value || 0).toLocaleString(undefined, {maximumFractionDigits});}
  function date(value) {if (!value) return 'Never'; const d = new Date(value); return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();}
  function bytes(value) {const n = Number(value || 0); if (n < 1024) return `${n} B`; if (n < 1048576) return `${num(n / 1024, 1)} KiB`; return `${num(n / 1048576, 1)} MiB`;}
  function percent(value) {return `${num(Number(value || 0) * 100, 1)}%`;}
  function badge(label, tone = '') {return node('span', {class: `badge ${tone}`}, node('span', {class: 'status-dot', 'aria-hidden': 'true'}), label);}
  function statusBadge(value) {const lower = String(value || 'Unknown').toLowerCase(); return badge(value || 'Unknown', ['online', 'available', 'enabled', 'published', 'success'].includes(lower) ? 'good' : ['offline', 'unavailable', 'failure', 'error'].includes(lower) ? 'bad' : lower === 'degraded' ? 'warn' : '');}
  function nameCell(title, subtitle) {return node('div', {}, node('strong', {}, title || '—'), subtitle ? node('span', {class: 'secondary'}, subtitle) : null);}
  function notice(message, tone = '') {return node('div', {class: `notice ${tone}`, role: tone === 'error' ? 'alert' : 'status'}, message);}
  function toast(message, error = false) {
    const entry = node('div', {class: `toast ${error ? 'error' : ''}`}, node('span', {}, message));
    entry.append(button('×', () => entry.remove(), 'quiet small', {'aria-label': 'Dismiss notification'}));
    notifications.append(entry);
    setTimeout(() => entry.remove(), error ? 12000 : 6500);
  }
  async function run(task) {try {await task();} catch (error) {if (error.status === 401 && state.admin) await showAuth(false, 'Your session has expired. Sign in again.'); else toast(error.message || 'The operation failed.', true);}}
  async function api(path, options = {}) {
    const method = options.method || 'GET';
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (method !== 'GET') headers.set('X-CSRF-Token', state.csrf);
    let body = options.body;
    if (body !== undefined && !(body instanceof Blob)) {headers.set('Content-Type', 'application/json'); body = JSON.stringify(body);}
    let response;
    try {response = await fetch(`/admin/api/${path}`, {method, headers, body, credentials: 'same-origin', cache: 'no-store'});} catch (_) {throw new Error('Cannot reach the gateway. Check the listener address and try again.');}
    let payload;
    try {payload = await response.json();} catch (_) {throw new Error('The gateway returned an unreadable response.');}
    if (!response.ok) {const error = new Error(payload?.error?.message || `Request failed (${response.status}).`); error.status = response.status; throw error;}
    return payload;
  }
  async function items(resource) {return (await api(resource)).items || [];}
  function closeEditor() {
    for (const input of dialog.querySelectorAll('input[type="password"], .secret-input')) input.value = '';
    if (dialog.open) dialog.close();
    dialog.replaceChildren();
  }
  dialog.addEventListener('cancel', event => {event.preventDefault(); closeEditor();});
  window.addEventListener('pagehide', closeEditor);

  function formField(parent, label, name, value = '', options = {}) {
    const wrap = node('label', {class: `field ${options.full ? 'full' : ''}`});
    wrap.append(node('span', {class: 'field-label'}, label));
    const tag = options.textarea ? 'textarea' : 'input';
    const input = node(tag, {name, type: options.type || 'text', required: options.required, placeholder: options.placeholder, autocomplete: options.autocomplete || 'off', min: options.min, max: options.max, step: options.step, minlength: options.minLength, maxlength: options.maxLength, readOnly: options.readOnly, spellcheck: options.spellcheck === true ? 'true' : 'false', rows: options.rows});
    input.value = value ?? '';
    wrap.append(input);
    if (options.help) wrap.append(node('small', {}, options.help));
    parent.append(wrap);
    return input;
  }
  function selectField(parent, label, name, values, selected = '', help = '') {
    const wrap = node('label', {class: 'field'}, node('span', {class: 'field-label'}, label));
    const select = node('select', {name});
    for (const [value, title] of values) select.append(node('option', {value}, title));
    select.value = String(selected);
    wrap.append(select);
    if (help) wrap.append(node('small', {}, help));
    parent.append(wrap);
    return select;
  }
  function check(parent, label, name, checked = false, help = '', value = 'on') {
    const input = node('input', {type: 'checkbox', name, value, checked});
    parent.append(node('label', {class: 'check'}, input, node('span', {}, node('strong', {}, label), help ? node('small', {}, help) : null)));
    return input;
  }
  function formSection(parent, title, description = '') {
    const section = node('fieldset', {class: 'form-section'}, node('legend', {}, title));
    if (description) section.append(node('p', {}, description));
    parent.append(section); return section;
  }
  function openEditor(title, description, build, onSubmit, submitLabel = 'Save changes') {
    closeEditor();
    const heading = node('div', {class: 'dialog-header'}, node('div', {}, node('h2', {id: 'dialog-title'}, title), node('p', {}, description)), button('×', closeEditor, 'quiet icon', {'aria-label': 'Close dialog'}));
    const form = node('form', {class: 'dialog-body'});
    build(form);
    const errorBox = notice('', 'error'); errorBox.hidden = true;
    const submit = node('button', {type: 'submit', class: 'button primary'}, submitLabel);
    form.append(errorBox, node('div', {class: 'form-actions'}, button('Cancel', closeEditor), submit));
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (!form.reportValidity() || submit.disabled) return;
      errorBox.hidden = true; submit.disabled = true; submit.textContent = 'Saving…';
      try {
        const result = (await onSubmit(form)) || {};
        if (result.cancelled) return;
        closeEditor();
        if (result.message) toast(result.message);
        if (result.refresh !== false && state.admin) await showPage(state.page);
        if (result.after) await result.after();
      } catch (error) {
        if (error.status === 401) {await showAuth(false, 'Your session has expired. Sign in again.'); return;}
        errorBox.textContent = error.message || 'The operation failed.'; errorBox.hidden = false; errorBox.scrollIntoView({block: 'nearest'});
      } finally {submit.disabled = false; submit.textContent = submitLabel;}
    });
    dialog.append(heading, form); dialog.showModal();
  }
  function formValue(form, name) {return String(new FormData(form).get(name) || '').trim();}
  function passwordValue(form, name = 'password') {return String(new FormData(form).get(name) || '');}
  function checkedValue(form, name) {return new FormData(form).has(name);}
  function lines(value) {return [...new Set(String(value).split(/[\n,]+/).map(v => v.trim()).filter(Boolean))];}

  async function showAuth(setup = false, message = '') {
    state.admin = null; state.csrf = ''; state.render++; closeEditor();
    const card = node('section', {class: 'auth-card'}, brand(), node('h1', {}, setup ? 'Make this gateway yours.' : 'Welcome back.'), node('p', {}, setup ? 'Create the first administrator account. Initial setup is available from localhost only.' : 'Sign in to manage your local models and access.'));
    if (message) card.append(notice(message));
    const form = node('form');
    formField(form, 'Username', 'username', '', {required: true, maxLength: 128, autocomplete: 'username', placeholder: 'Your username'});
    formField(form, 'Password', 'password', '', {type: 'password', required: true, minLength: setup ? 12 : undefined, maxLength: 1024, autocomplete: setup ? 'new-password' : 'current-password', help: setup ? 'Use at least 12 characters.' : ''});
    if (setup) formField(form, 'Confirm password', 'confirm_password', '', {type: 'password', required: true, minLength: 12, autocomplete: 'new-password'});
    const errorBox = notice('', 'error'); errorBox.hidden = true;
    const submit = node('button', {type: 'submit', class: 'button primary', disabled: true}, setup ? 'Create administrator' : 'Sign in');
    form.append(errorBox, submit); card.append(form);
    card.append(node('div', {class: 'auth-footer'}, setup ? link('Already set up? Sign in', '/admin/login') : link('First time here? Set up your gateway', '/setup')));
    app.replaceChildren(node('main', {id: 'main', class: 'auth-shell'}, card));
    document.title = `${setup ? 'Setup' : 'Sign in'} · LLM Gateway`;
    try {state.csrf = (await api('csrf')).csrf_token; submit.disabled = false;} catch (error) {errorBox.textContent = error.message; errorBox.hidden = false; card.append(button('Retry connection', () => showAuth(setup, message)));}
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (submit.disabled || !form.reportValidity()) return;
      errorBox.hidden = true;
      const password = passwordValue(form);
      if (setup && password !== passwordValue(form, 'confirm_password')) {errorBox.textContent = 'The passwords do not match.'; errorBox.hidden = false; return;}
      submit.disabled = true;
      try {
        const session = await api(setup ? 'setup' : 'login', {method: 'POST', body: {username: formValue(form, 'username'), password}});
        state.admin = session.admin; state.csrf = session.csrf_token;
        form.querySelectorAll('input[type="password"]').forEach(input => {input.value = '';});
        history.replaceState(null, '', '/admin/#dashboard');
        shell(); await showPage('dashboard');
      } catch (error) {errorBox.textContent = error.message; errorBox.hidden = false;} finally {submit.disabled = false;}
    });
  }
  function brand() {return node('div', {class: 'brand'}, node('span', {class: 'brand-mark', 'aria-hidden': 'true'}, 'L'), node('div', {}, 'LLM Gateway', node('small', {}, 'Local inference, connected')));}
  function shell() {
    const nav = node('nav', {class: 'nav', 'aria-label': 'Administration'});
    for (const [id, label, icon, group] of sections) {
      if (group) nav.append(node('div', {class: 'nav-label'}, group));
      const entry = link('', `#${id}`, 'nav-link'); entry.dataset.page = id;
      entry.append(node('span', {class: 'nav-icon', 'aria-hidden': 'true'}, icon), label); nav.append(entry);
    }
    const logout = async () => {await api('logout', {method: 'POST', body: {}}); history.replaceState(null, '', '/admin/login'); await showAuth(false);};
    const sidebar = node('aside', {class: 'sidebar'}, brand(), nav,
      node('div', {class: 'sidebar-footer'}, node('div', {class: 'account'}, node('strong', {}, state.admin.username), button('Sign out', logout, 'quiet small')), node('p', {}, 'Private by configuration. Local by design.')));
    state.title = node('strong', {}, 'Overview');
    const topbar = node('header', {class: 'topbar'}, node('div', {class: 'breadcrumb'}, 'Workspace', node('span', {'aria-hidden': 'true'}, '/'), state.title), node('div', {class: 'inline'}, node('span', {class: 'server-address'}, location.host), button('Sign out', logout, 'quiet small', {'aria-label': `Sign out ${state.admin.username}`})));
    state.main = node('main', {id: 'main', class: 'main', tabindex: '-1'});
    app.replaceChildren(node('div', {class: 'layout'}, sidebar, node('div', {class: 'workspace'}, topbar, state.main)));
  }
  async function showPage(page) {
    if (!state.admin) return;
    if (!sections.some(section => section[0] === page)) page = 'dashboard';
    state.page = page; closeEditor(); const revision = ++state.render;
    const title = sections.find(section => section[0] === page)[1];
    state.title.textContent = title; document.title = `${title} · LLM Gateway`;
    for (const entry of app.querySelectorAll('.nav-link')) {if (entry.dataset.page === page) entry.setAttribute('aria-current', 'page'); else entry.removeAttribute('aria-current');}
    state.main.replaceChildren(node('div', {class: 'loading', role: 'status'}, 'Loading…'));
    try {
      const content = await views[page]();
      if (revision === state.render && state.admin) state.main.replaceChildren(content);
    } catch (error) {
      if (revision !== state.render) return;
      if (error.status === 401) {await showAuth(false, 'Your session has expired. Sign in again.'); return;}
      state.main.replaceChildren(pageHeader(page), notice(error.message, 'error'), button('Try again', () => showPage(page)));
    }
  }
  function pageHeader(page, actions = []) {
    const title = sections.find(section => section[0] === page)[1];
    return node('div', {class: 'page-header'}, node('div', {}, node('h1', {}, title), node('p', {}, descriptions[page])), node('div', {class: 'page-actions'}, button('↻ Refresh', () => showPage(page)), ...actions));
  }
  function pageContainer(page, actions = []) {return node('div', {}, pageHeader(page, actions));}
  function emptyState(title, description, action = null) {return node('div', {class: 'empty'}, node('span', {class: 'empty-symbol', 'aria-hidden': 'true'}, '◇'), node('strong', {}, title), node('p', {}, description), action);}
  function table(columns, rows, empty = 'No matching records.') {
    const element = node('table'); element.append(node('thead', {}, node('tr', {}, columns.map(column => node('th', {scope: 'col', class: column.actions ? 'table-actions' : ''}, column.label)))));
    const body = node('tbody');
    for (const row of rows) body.append(node('tr', {}, columns.map(column => node('td', {class: column.actions ? 'table-actions' : ''}, column.render ? column.render(row) : String(row[column.key] ?? '—')))));
    if (!rows.length) body.append(node('tr', {}, node('td', {colspan: columns.length}, emptyState(empty, 'Try a different filter or add your first record.'))));
    element.append(body); return node('div', {class: 'table-wrap'}, element);
  }
  function collectionPanel(rows, columns, options = {}) {
    const panel = node('section', {class: 'panel'});
    const search = node('input', {type: 'search', class: 'search', placeholder: options.placeholder || 'Filter by name or details…', 'aria-label': 'Filter table'});
    const count = node('span', {class: 'count'});
    const body = node('div');
    const paint = () => {const query = search.value.toLowerCase().trim(); const filtered = rows.filter(row => !query || JSON.stringify(row).toLowerCase().includes(query)); count.textContent = `${num(filtered.length)} ${options.noun || 'records'}`; body.replaceChildren(table(columns, filtered, options.empty || 'Nothing here yet.'));};
    search.addEventListener('input', paint);
    panel.append(node('div', {class: 'toolbar'}, search, count), body); paint(); return panel;
  }
  function rowActions(...actions) {return node('div', {class: 'row-actions'}, ...actions);}
  async function remove(resource, record, label) {
    if (!confirm(`Delete ${label}? This cannot be undone.`)) return;
    await api(`${resource}/${encodeURIComponent(record.id)}`, {method: 'DELETE'}); toast(`${label} deleted.`); await showPage(state.page);
  }

  async function dashboardView() {
    const [data, engines] = await Promise.all([api('dashboard'), items('engines')]);
    const page = pageContainer('dashboard');
    const cards = [
      ['Requests today', num(data.today_requests), `${num(data.streaming_requests)} streamed · UTC day`],
      ['Tokens today', num(data.total_tokens), `${num(data.input_tokens)} input · ${num(data.output_tokens)} output`],
      ['Published models', num(data.published_models), `${num(data.unavailable_models)} unavailable`],
      ['Connected engines', `${num(data.online)} / ${num(data.engines)}`, `${num(data.offline)} offline · ${num(data.degraded)} degraded`]
    ];
    page.append(node('div', {class: 'stats-grid'}, cards.map(([label, value, detail]) => node('article', {class: 'stat-card'}, node('div', {class: 'stat-label'}, label), node('div', {class: 'stat-value'}, value), node('div', {class: 'stat-detail'}, detail)))));
    const health = node('section', {class: 'panel'}, node('div', {class: 'panel-heading'}, node('div', {}, node('h2', {}, 'Engine health'), node('p', {}, 'Latest model discovery checks')), link('Manage engines →', '#engines')));
    const healthBody = node('div', {class: 'panel-body'});
    if (!engines.length) healthBody.append(emptyState('Connect your first engine', 'Add an API endpoint to start discovering local models.', button('Add engine', () => engineEditor(), 'primary')));
    for (const engine of engines) healthBody.append(node('div', {class: 'summary-row'}, nameCell(engine.name, engine.enabled ? `${num(engine.latency_ms, 1)} ms · ${date(engine.last_check)}` : 'Disabled'), statusBadge(engine.enabled ? engine.status : 'Disabled')));
    health.append(healthBody);
    const performance = node('section', {class: 'panel'}, node('div', {class: 'panel-heading'}, node('div', {}, node('h2', {}, 'Today’s performance'), node('p', {}, 'Completed request statistics'))), node('div', {class: 'panel-body'},
      node('div', {class: 'metrics'}, [['Error rate', percent(data.error_rate)], ['Avg. response', `${num(data.average_response_ms, 0)} ms`], ['API keys', num(data.api_keys)]].map(([label, value]) => node('div', {class: 'metric'}, node('div', {class: 'metric-label'}, label), node('div', {class: 'metric-value'}, value)))),
      node('hr'), node('h3', {}, 'From local model to shared API'),
      node('ol', {class: 'quick-start'}, [['Connect an engine', 'Use the API base URL exposed by your inference server.', 'engines'], ['Publish a model alias', 'Review capabilities and choose its IP and API-key restrictions.', 'models'], ['Connect your applications', `Use ${location.origin}/v1 as your API base URL.`, 'keys']].map(([title, text, target], index) => node('li', {}, node('span', {class: 'step'}, index + 1), node('div', {}, link(title, `#${target}`), node('p', {}, text)))))));
    page.append(node('div', {class: 'overview-grid'}, health, performance)); return page;
  }

  async function enginesView() {
    const engines = await items('engines'); const page = pageContainer('engines', [button('+ Add engine', () => engineEditor(), 'primary')]);
    page.append(collectionPanel(engines, [
      {label: 'Engine', render: row => nameCell(row.name, row.base_url)},
      {label: 'Profile', render: row => nameCell(row.type, row.detected_type ? `Detected: ${row.detected_type}` : 'Not detected')},
      {label: 'Status', render: row => node('div', {}, statusBadge(row.enabled ? row.status : 'Disabled'), row.last_error ? node('span', {class: 'secondary'}, row.last_error) : null)},
      {label: 'Last check', render: row => nameCell(date(row.last_check), `${num(row.latency_ms, 1)} ms`)},
      {label: 'Actions', actions: true, render: row => rowActions(button('Check', btn => engineAction(row, 'check', btn), 'small', {disabled: !row.enabled}), button('Sync', btn => engineAction(row, 'sync', btn), 'small', {disabled: !row.enabled}), button('Edit', () => engineEditor(row), 'small'), button('Delete', () => remove('engines', row, `engine “${row.name}”`), 'small quiet'))}
    ], {noun: 'engines', empty: 'No engines connected.'})); return page;
  }
  async function engineAction(engine, action, btn) {
    btn.disabled = true;
    try {const result = await api(`engines/${encodeURIComponent(engine.id)}/${action}`, {method: 'POST', body: {}}); toast(`${engine.name}: ${result.status}${result.last_error ? ` — ${result.last_error}` : action === 'sync' ? '. Model discovery updated.' : '.'}`, result.status !== 'Online'); await showPage(state.page);} finally {btn.disabled = false;}
  }
  function engineEditor(engine = null) {
    openEditor(engine ? 'Edit engine' : 'Connect an engine', 'Point the gateway at a running inference server.', form => {
      const grid = node('div', {class: 'field-grid'}); form.append(grid);
      formField(grid, 'Name', 'name', engine?.name || '', {required: true, maxLength: 200, placeholder: 'Studio on Mac mini'});
      selectField(grid, 'Engine profile', 'type', [['auto', 'Auto detect'], ['generic', 'Generic OpenAI-compatible'], ['lmstudio', 'LM Studio'], ['omlx', 'oMLX'], ['mlxserve', 'MLX LM server']], engine?.type || 'auto');
      formField(form, 'API base URL', 'base_url', engine?.base_url || 'http://127.0.0.1:1234/v1', {type: 'url', required: true, help: 'HTTP or HTTPS, including an optional /v1 path. Credentials, queries, and fragments are not accepted.'});
      const auth = selectField(form, 'Authentication', 'auth_type', [['none', 'None'], ['bearer', 'Bearer token'], ['x-api-key', 'X-API-Key']], engine?.auth_type || 'none');
      const secret = formField(form, engine?.has_secret ? 'Replace saved secret' : 'Engine secret', 'secret', '', {type: 'password', autocomplete: 'new-password', help: engine?.has_secret ? 'Leave blank to keep the saved secret.' : 'Use the credential configured on the engine.'});
      const update = () => {secret.required = auth.value !== 'none' && !engine?.has_secret; secret.closest('.field').hidden = auth.value === 'none';}; auth.addEventListener('change', update); update();
      check(form, 'Engine enabled', 'enabled', engine ? engine.enabled : true, 'Disabled engines are unavailable to clients.');
      if (engine?.has_secret) check(form, 'Clear the saved secret', 'clear_secret', false, 'Choose no authentication, or provide a replacement secret.');
    }, async form => {
      const data = {name: formValue(form, 'name'), type: formValue(form, 'type'), base_url: formValue(form, 'base_url'), auth_type: formValue(form, 'auth_type'), secret: passwordValue(form, 'secret'), clear_secret: checkedValue(form, 'clear_secret'), enabled: checkedValue(form, 'enabled')};
      const parsed = new URL(data.base_url); if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash || data.base_url.includes('?') || data.base_url.includes('#')) throw new Error('Use an HTTP(S) URL without credentials, a query, or a fragment.');
      if (data.auth_type === 'none') data.secret = '';
      const saved = await api(engine ? `engines/${encodeURIComponent(engine.id)}` : 'engines', {method: engine ? 'PUT' : 'POST', body: data});
      if (!engine && saved.enabled) {
        try {const checked = await api(`engines/${encodeURIComponent(saved.id)}/sync`, {method: 'POST', body: {}}); return {message: `Engine saved. ${checked.status === 'Online' ? 'Models discovered.' : 'Use Check to review the connection.'}`};}
        catch (_) {return {message: 'Engine saved. Discovery did not finish; use Sync to try again.'};}
      }
      return {message: 'Engine saved.'};
    }, engine ? 'Save engine' : 'Connect engine');
  }

  async function discoveryView() {
    const [upstreams, engines] = await Promise.all([items('upstream-models'), items('engines')]); const byID = new Map(engines.map(engine => [engine.id, engine]));
    const page = pageContainer('upstream-models', [link('Manage engines', '#engines', 'button primary')]);
    page.append(collectionPanel(upstreams, [
      {label: 'Upstream model', render: row => nameCell(row.display_name || row.upstream_id, row.upstream_id)},
      {label: 'Engine', render: row => byID.get(row.engine_id)?.name || row.engine_id},
      {label: 'Availability', render: row => statusBadge(row.available ? 'Available' : 'Unavailable')},
      {label: 'Capabilities', render: row => node('div', {class: 'tag-list'}, Object.entries(row.capabilities || {}).filter(([, enabled]) => enabled).map(([key]) => badge(capabilityNames[key] || key)))},
      {label: 'Registration', render: row => badge(row.registered ? 'Registered' : 'Not registered', row.registered ? 'good' : '')},
      {label: 'Actions', actions: true, render: row => button(row.registered ? 'Add another alias' : 'Register model', () => modelEditor(null, row), 'small', {disabled: !row.available})}
    ], {noun: 'upstream models', empty: 'No upstream models discovered.'})); return page;
  }
  async function modelsView() {
    const [models, engines] = await Promise.all([items('models'), items('engines')]); const names = new Map(engines.map(engine => [engine.id, engine.name]));
    const page = pageContainer('models', [button('+ Register model', () => modelEditor(), 'primary')]);
    page.append(collectionPanel(models, [
      {label: 'Public alias', render: row => nameCell(row.alias, row.display_name || row.upstream_model_id)},
      {label: 'Engine / upstream', render: row => nameCell(names.get(row.engine_id) || row.engine_id, row.upstream_model_id)},
      {label: 'Publication', render: row => badge(row.published ? 'Published' : 'Hidden', row.published ? 'good' : '')},
      {label: 'Availability', render: row => statusBadge(row.available ? 'Available' : 'Unavailable')},
      {label: 'Access', render: row => nameCell(row.allowed_ips?.length ? `${row.allowed_ips.length} IP rules` : 'Any source IP', row.allowed_api_keys?.length ? `${row.allowed_api_keys.length} allowed API keys` : 'No API key required')},
      {label: 'Actions', actions: true, render: row => rowActions(button('Edit', () => modelEditor(row), 'small'), button('Delete', () => remove('models', row, `model “${row.alias}”`), 'small quiet'))}
    ], {noun: 'models', empty: 'No public aliases registered.'})); return page;
  }
  async function modelEditor(model = null, preset = null) {
    const [upstreams, engines, keys] = await Promise.all([items('upstream-models'), items('engines'), items('keys')]);
    const engineNames = new Map(engines.map(engine => [engine.id, engine.name]));
    if (model && !upstreams.some(up => up.engine_id === model.engine_id && up.upstream_id === model.upstream_model_id)) upstreams.push({engine_id: model.engine_id, upstream_id: model.upstream_model_id, available: model.available, capabilities: model.capabilities});
    if (!upstreams.length) {toast('Connect an engine and sync its models before registering an alias.', true); return;}
    const wantedEngine = preset?.engine_id || model?.engine_id;
    const wantedModel = preset?.upstream_id || model?.upstream_model_id;
    const initial = upstreams.find(up => up.engine_id === wantedEngine && up.upstream_id === wantedModel) || upstreams.find(up => up.available) || upstreams[0];
    let selected = initial;
    const capInputs = new Map();
    openEditor(model ? 'Edit model alias' : 'Register a model', 'Publish a stable name with the capabilities and access rules you choose.', form => {
      const selector = selectField(form, 'Upstream model', 'upstream', upstreams.map((up, index) => [index, `${engineNames.get(up.engine_id) || up.engine_id} / ${up.upstream_id}${up.available ? '' : ' (unavailable)'}`]), upstreams.indexOf(initial));
      const grid = node('div', {class: 'field-grid'}); form.append(grid);
      const alias = formField(grid, 'Public alias', 'alias', model?.alias || '', {required: true, maxLength: 200, placeholder: 'local-assistant', help: 'Client requests use this model name. No whitespace.'});
      const display = formField(grid, 'Display name', 'display_name', model?.display_name || initial.display_name || '', {placeholder: 'My local assistant'});
      check(form, 'Publish this model', 'published', model?.published || false, 'Published, available models appear to authorized clients.');
      const caps = formSection(form, 'Capabilities', 'Defaults are inferred from metadata. Enable only features supported by your engine and model.');
      const capGrid = node('div', {class: 'check-grid'}); caps.append(capGrid);
      const initialCaps = {...initial.capabilities, ...(model?.capabilities || {}), models: model ? model.capabilities?.models !== false : true};
      for (const [key, label] of Object.entries(capabilityNames)) capInputs.set(key, check(capGrid, label, `cap_${key}`, Boolean(initialCaps[key])));
      selector.addEventListener('change', () => {selected = upstreams[Number(selector.value)]; for (const [key, input] of capInputs) input.checked = key === 'models' || Boolean(selected.capabilities?.[key]); if (!model && !display.value) display.value = selected.display_name || '';});
      const access = formSection(form, 'Access controls', 'IP and API-key rules are combined: both must allow a request. An empty list adds no restriction.');
      formField(access, 'Allowed IP addresses or CIDRs', 'allowed_ips', model ? (model.allowed_ips || []).join('\n') : '127.0.0.1/32\n::1/128', {textarea: true, rows: 3, placeholder: '127.0.0.1/32\n::1/128', help: 'One IP address or CIDR per line. New models default to localhost.'});
      access.append(node('span', {class: 'field-label'}, 'Allowed API keys'));
      if (!keys.length) access.append(node('p', {class: 'muted'}, 'No API keys exist. Create one in API keys to require authentication.'));
      const list = node('div', {class: 'check-list'});
      for (const key of keys) check(list, key.name, 'allowed_api_keys', Boolean(model?.allowed_api_keys?.includes(key.id)), `${key.masked || ''}${key.enabled ? '' : ' · disabled'}`, key.id);
      if (keys.length) access.append(list);
      alias.addEventListener('input', () => alias.setCustomValidity(/\s/.test(alias.value) ? 'Use an alias without whitespace.' : ''));
    }, async form => {
      const ips = lines(formValue(form, 'allowed_ips'));
      const allowedKeys = new FormData(form).getAll('allowed_api_keys').map(String);
      const changes = [];
      if (!ips.length && (!model || model.allowed_ips?.length)) changes.push('allow any source IP');
      if (!allowedKeys.length && model?.allowed_api_keys?.length) changes.push('remove the API-key requirement');
      if (changes.length && !confirm(`This change will ${changes.join(' and ')} for this model. Continue?`)) return {cancelled: true};
      const capabilities = Object.fromEntries([...capInputs].map(([key, input]) => [key, input.checked]));
      await api(model ? `models/${encodeURIComponent(model.id)}` : 'models', {method: model ? 'PUT' : 'POST', body: {alias: formValue(form, 'alias'), display_name: formValue(form, 'display_name'), engine_id: selected.engine_id, upstream_model_id: selected.upstream_id, available: Boolean(selected.available), published: checkedValue(form, 'published'), capabilities, allowed_ips: ips, allowed_api_keys: allowedKeys}});
      return {message: 'Model alias saved.'};
    }, model ? 'Save model' : 'Register model');
  }

  async function keysView() {
    const keys = await items('keys'); const page = pageContainer('keys', [button('+ Create API key', () => keyEditor(), 'primary')]);
    page.append(collectionPanel(keys, [
      {label: 'API key', render: row => nameCell(row.name, row.masked)},
      {label: 'Tags', render: row => node('div', {class: 'tag-list'}, (row.tags || []).map(tag => badge(tag)))},
      {label: 'Status', render: row => statusBadge(row.enabled ? 'Enabled' : 'Disabled')},
      {label: 'Last used', render: row => date(row.last_used_at)},
      {label: 'Actions', actions: true, render: row => rowActions(button('Reveal', () => revealKey(row), 'small'), button('Edit', () => keyEditor(row), 'small'), button(row.enabled ? 'Disable' : 'Enable', () => toggleKey(row), 'small'), button('Delete', () => remove('keys', row, `API key “${row.name}”`), 'small quiet'))}
    ], {noun: 'API keys', empty: 'No client API keys yet.'})); return page;
  }
  function keyEditor(key = null) {
    openEditor(key ? 'Edit API key' : 'Create an API key', 'API keys authenticate clients. Model access is managed on each model.', form => {
      formField(form, 'Name', 'name', key?.name || '', {required: true, maxLength: 200, placeholder: 'Development laptop'});
      formField(form, 'Tags', 'tags', (key?.tags || []).join(', '), {placeholder: 'development, personal', help: 'Separate tags with commas. Tags also appear in usage statistics.'});
      check(form, 'Key enabled', 'enabled', key ? key.enabled : true);
    }, async form => {
      const result = await api(key ? `keys/${encodeURIComponent(key.id)}` : 'keys', {method: key ? 'PUT' : 'POST', body: {name: formValue(form, 'name'), tags: lines(formValue(form, 'tags')), enabled: checkedValue(form, 'enabled')}});
      return {message: key ? 'API key saved.' : 'API key created.', after: key ? null : () => revealKey(result)};
    }, key ? 'Save API key' : 'Create API key');
  }
  async function toggleKey(key) {
    await api(`keys/${encodeURIComponent(key.id)}`, {method: 'PUT', body: {name: key.name, tags: key.tags || [], enabled: !key.enabled}}); toast(`API key ${key.enabled ? 'disabled' : 'enabled'}.`); await showPage('keys');
  }
  async function revealKey(key) {
    const page = state.page; const result = await api(`keys/${encodeURIComponent(key.id)}/reveal`, {method: 'POST', body: {}});
    if (page !== state.page || !state.admin) return;
    closeEditor();
    const input = node('input', {type: 'text', class: 'secret-input', readOnly: true, 'aria-label': 'API key secret', autocomplete: 'off'}); input.value = result.secret;
    const copy = button('Copy key', async () => {if (!navigator.clipboard?.writeText) {input.focus(); input.select(); toast('Key selected. Copy it with your keyboard.'); return;} await navigator.clipboard.writeText(input.value); toast('API key copied.');}, 'primary');
    dialog.append(node('div', {class: 'dialog-header'}, node('div', {}, node('h2', {id: 'dialog-title'}, key.name), node('p', {}, 'This secret is hidden when you close this dialog or navigate away.')), button('×', closeEditor, 'quiet icon', {'aria-label': 'Hide API key'})), node('div', {class: 'dialog-body'}, input, node('div', {class: 'form-actions'}, button('Hide key', closeEditor), copy)));
    dialog.showModal(); input.focus(); input.select();
  }

  async function adminsView() {
    const admins = await items('admins'); const page = pageContainer('admins', [button('+ Add administrator', () => adminEditor(), 'primary')]);
    page.append(collectionPanel(admins, [
      {label: 'Administrator', render: row => nameCell(row.username, row.id === state.admin.id ? 'Your account' : 'Administrator')},
      {label: 'Created', render: row => date(row.created_at)},
      {label: 'Actions', actions: true, render: row => rowActions(button('Change password', () => adminEditor(row), 'small'), button('Delete', async () => {const own = row.id === state.admin.id; if (!confirm(`Delete administrator “${row.username}”${own ? ' and sign yourself out' : ''}?`)) return; await api(`admins/${encodeURIComponent(row.id)}`, {method: 'DELETE'}); if (own) await showAuth(false, 'Your administrator account was deleted.'); else {toast('Administrator deleted.'); await showPage('admins');}}, 'small quiet', {disabled: admins.length <= 1, title: admins.length <= 1 ? 'The last administrator cannot be deleted.' : 'Delete administrator'}))}
    ], {noun: 'administrators'})); return page;
  }
  function adminEditor(admin = null) {
    openEditor(admin ? `Change password for ${admin.username}` : 'Add an administrator', admin ? 'Changing a password signs this administrator out of every session.' : 'All administrators have full gateway access.', form => {
      if (!admin) formField(form, 'Username', 'username', '', {required: true, maxLength: 128, autocomplete: 'username'});
      formField(form, 'New password', 'password', '', {type: 'password', required: true, minLength: 12, maxLength: 1024, autocomplete: 'new-password', help: 'Use 12–1024 characters.'});
      formField(form, 'Confirm password', 'confirm_password', '', {type: 'password', required: true, minLength: 12, autocomplete: 'new-password'});
    }, async form => {
      const password = passwordValue(form); if (password !== passwordValue(form, 'confirm_password')) throw new Error('The passwords do not match.');
      await api(admin ? `admins/${encodeURIComponent(admin.id)}` : 'admins', {method: admin ? 'PUT' : 'POST', body: {username: admin?.username || formValue(form, 'username'), password}});
      if (admin?.id === state.admin.id) return {refresh: false, after: () => showAuth(false, 'Password changed. Sign in with your new password.')};
      return {message: admin ? 'Password changed and sessions revoked.' : 'Administrator created.'};
    }, admin ? 'Change password' : 'Create administrator');
  }

  async function statisticsView() {
    const page = pageContainer('statistics'); const panel = node('section', {class: 'panel'}); const controls = node('div', {class: 'toolbar-controls'});
    const group = node('select', {'aria-label': 'Group statistics'}); [['day', 'By day'], ['model', 'By model'], ['engine', 'By engine'], ['api_key', 'By API key']].forEach(([value, label]) => group.append(node('option', {value}, label)));
    const days = node('select', {'aria-label': 'Statistics period'}); [[7, 'Last 7 days'], [30, 'Last 30 days'], [90, 'Last 90 days'], [365, 'Last year']].forEach(([value, label]) => days.append(node('option', {value}, label))); days.value = '30';
    controls.append(group, days); const count = node('span', {class: 'count'}); const results = node('div'); panel.append(node('div', {class: 'toolbar'}, controls, count), results); page.append(panel);
    let request = 0;
    const refresh = async () => {const current = ++request; results.replaceChildren(node('div', {class: 'loading'}, 'Loading statistics…')); try {const data = await api(`statistics?group=${encodeURIComponent(group.value)}&days=${days.value}`); if (current !== request) return; const rows = data.items || []; count.textContent = `${rows.length} groups`; results.replaceChildren(table([
      {label: group.options[group.selectedIndex].textContent.slice(3), render: row => nameCell(row.name || row.key || 'Anonymous / deleted', row.api_key_tags?.join(', '))},
      {label: 'Requests', render: row => num(row.requests)}, {label: 'Errors', render: row => nameCell(num(row.errors), percent(row.error_rate))},
      {label: 'Input tokens', render: row => num(row.input_tokens)}, {label: 'Output tokens', render: row => num(row.output_tokens)}, {label: 'Total tokens', render: row => num(row.total_tokens)},
      {label: 'Avg. response', render: row => `${num(row.average_response_ms, 1)} ms`}, {label: 'Streams', render: row => num(row.streaming_requests)}
    ], rows, 'No usage in this period.'));} catch (error) {results.replaceChildren(notice(error.message, 'error')); if (error.status === 401) await showAuth(false, 'Sign in to continue.');}};
    group.addEventListener('change', () => run(refresh)); days.addEventListener('change', () => run(refresh)); await refresh(); return page;
  }

  async function logsView(audit = false) {
    const resource = audit ? 'audit-logs' : 'access-logs'; const page = pageContainer(resource); const panel = node('section', {class: 'panel'});
    const searchForm = node('form', {class: 'toolbar'}); const controls = node('div', {class: 'toolbar-controls'});
    const search = node('input', {type: 'search', class: 'search', placeholder: audit ? 'Search actor, action, result…' : 'Search model, engine, key, source…', 'aria-label': 'Search logs'});
    controls.append(search, node('button', {type: 'submit', class: 'button'}, 'Search')); const count = node('span', {class: 'count'}); searchForm.append(controls, count);
    const content = node('div'); const pager = node('div', {class: 'pagination'}); let pageNumber = 1; let total = 0; let query = ''; let request = 0;
    const detail = row => {closeEditor(); const list = node('dl', {class: 'details-grid'}); for (const [key, value] of Object.entries(row)) if (key !== 'prompt') list.append(node('dt', {}, key.replaceAll('_', ' ')), node('dd', {}, Array.isArray(value) ? value.join(', ') : typeof value === 'object' && value !== null ? JSON.stringify(value, null, 2) : String(value ?? '—'))); dialog.append(node('div', {class: 'dialog-header'}, node('h2', {id: 'dialog-title'}, audit ? 'Audit event' : 'Request details'), button('×', closeEditor, 'quiet icon', {'aria-label': 'Close details'})), node('div', {class: 'dialog-body'}, list)); dialog.showModal();};
    const refresh = async () => {
      const current = ++request; content.replaceChildren(node('div', {class: 'loading'}, 'Loading logs…'));
      const data = await api(`${resource}?q=${encodeURIComponent(query)}&page=${pageNumber}&page_size=25`); if (current !== request) return; total = data.total || 0; count.textContent = `${num(total)} records`;
      const columns = audit ? [
        {label: 'Time', render: row => date(row.timestamp)}, {label: 'Actor', render: row => nameCell(row.actor_name || 'System', row.source_ip)},
        {label: 'Action', key: 'action'}, {label: 'Target', key: 'target'}, {label: 'Result', render: row => statusBadge(row.result)}
      ] : [
        {label: 'Time', render: row => date(row.timestamp)}, {label: 'Model', render: row => nameCell(row.model_alias || '—', row.engine_name)},
        {label: 'Client', render: row => nameCell(row.api_key_name || 'Anonymous', row.source_ip)}, {label: 'Endpoint', render: row => nameCell(row.endpoint, row.streaming ? 'Streaming' : 'JSON')},
        {label: 'Status', render: row => node('div', {}, badge(String(row.status), row.error_code || row.status >= 400 ? 'bad' : 'good'), row.error_code ? node('span', {class: 'secondary'}, row.error_code) : null)},
        {label: 'Duration / TTFT', render: row => nameCell(`${num(row.duration_ms, 0)} ms`, row.streaming ? `${num(row.ttft_ms, 0)} ms to first data` : '')},
        {label: 'Tokens', render: row => num(row.total_tokens)}
      ];
      columns.push({label: 'Details', actions: true, render: row => button('View', () => detail(row), 'small')}); content.replaceChildren(table(columns, data.items || [], 'No log entries found.'));
      const pages = Math.max(1, Math.ceil(total / 25));
      pager.replaceChildren(node('span', {}, total ? `${num((pageNumber - 1) * 25 + 1)}–${num(Math.min(pageNumber * 25, total))} of ${num(total)}` : 'No records'), node('div', {class: 'inline'}, button('Previous', async () => {pageNumber--; await refresh();}, 'small', {disabled: pageNumber <= 1}), node('span', {}, `Page ${pageNumber} of ${pages}`), button('Next', async () => {pageNumber++; await refresh();}, 'small', {disabled: pageNumber >= pages})));
    };
    searchForm.addEventListener('submit', event => {event.preventDefault(); query = search.value.trim(); pageNumber = 1; run(refresh);});
    panel.append(searchForm, content, pager); page.append(panel, node('p', {class: 'muted'}, audit ? 'Search supports actor:, source:, action:, target:, and result: prefixes.' : 'Search supports model:, engine:, key:, source:, endpoint:, status:, request:, and error: prefixes.')); await refresh(); return page;
  }

  async function backupsView() {
    const backups = await items('backups'); const page = pageContainer('backups', [button('Import & restore', backupImport), button('+ Create backup', backupCreate, 'primary')]);
    page.append(notice('Local backups require this gateway’s original Keychain key. Portable backups include encrypted credentials and can be restored with their passphrase.'));
    page.append(collectionPanel(backups, [
      {label: 'Backup', render: row => nameCell(row.filename, row.id)}, {label: 'Kind', render: row => badge(row.kind, row.kind === 'portable' ? 'good' : '')},
      {label: 'Size', render: row => bytes(row.size)}, {label: 'Created', render: row => date(row.created_at)},
      {label: 'Actions', actions: true, render: row => rowActions(link('Download', `/admin/api/backups/${encodeURIComponent(row.id)}/download`, 'button small'), button('Restore', () => backupRestore(row), 'small'), button('Delete', () => remove('backups', row, `backup “${row.filename}”`), 'small quiet'))}
    ], {noun: 'backups', empty: 'No backups created yet.'})); return page;
  }
  function backupCreate() {
    openEditor('Create backup', 'Backups capture a consistent snapshot of gateway configuration and history.', form => {
      const kind = selectField(form, 'Backup kind', 'kind', [['local', 'Local — requires original Keychain'], ['portable', 'Portable — encrypted with passphrase']], 'local');
      const pass = formField(form, 'Portable backup passphrase', 'passphrase', '', {type: 'password', minLength: 12, autocomplete: 'new-password', help: 'At least 12 characters. Keep this passphrase to restore the backup.'});
      const confirmPass = formField(form, 'Confirm passphrase', 'confirm_passphrase', '', {type: 'password', autocomplete: 'new-password'});
      const update = () => {const portable = kind.value === 'portable'; pass.required = portable; confirmPass.required = portable; pass.disabled = !portable; confirmPass.disabled = !portable; pass.closest('.field').hidden = !portable; confirmPass.closest('.field').hidden = !portable;}; kind.addEventListener('change', update); update();
    }, async form => {
      const kind = formValue(form, 'kind'); const passphrase = kind === 'portable' ? passwordValue(form, 'passphrase') : '';
      if (kind === 'portable' && passphrase !== passwordValue(form, 'confirm_passphrase')) throw new Error('The passphrases do not match.');
      await api('backups', {method: 'POST', body: {kind, passphrase}}); return {message: 'Backup created.'};
    }, 'Create backup');
  }
  function restoreResult() {return {message: 'Restore staged. Restart the gateway to apply it.', after: () => {if (state.main) state.main.prepend(notice('Restore verified and staged. Restart LLM Gateway to apply the snapshot. Current settings remain active until restart.', 'warning'));}};}
  function backupRestore(backup) {
    openEditor('Restore backup', backup.filename, form => {
      form.append(notice('Restore replaces gateway data at the next restart and signs out all administrators. A pre-restore snapshot is kept for rollback.', 'warning'));
      if (backup.kind === 'portable') formField(form, 'Backup passphrase', 'passphrase', '', {type: 'password', required: true, autocomplete: 'off'});
    }, async form => {
      if (!confirm(`Stage backup “${backup.filename}” for restoration? Gateway data will be replaced on restart.`)) return {cancelled: true};
      await api(`backups/${encodeURIComponent(backup.id)}/restore`, {method: 'POST', body: {passphrase: passwordValue(form, 'passphrase')}}); return restoreResult();
    }, 'Verify & stage restore');
  }
  function backupImport() {
    openEditor('Import and restore', 'Upload a local or portable LLM Gateway backup.', form => {
      formField(form, 'Backup file', 'archive', '', {type: 'file', required: true, help: 'Choose a .sqlite local backup or .llmgwb portable backup.'});
      formField(form, 'Portable backup passphrase', 'passphrase', '', {type: 'password', autocomplete: 'off', help: 'Leave blank for a local backup using the original Keychain key.'});
      form.append(notice('The uploaded backup is validated before staging. Its data replaces gateway data at the next restart.', 'warning'));
    }, async form => {
      const archive = form.querySelector('input[type="file"]').files[0]; if (!archive) throw new Error('Choose a backup file.');
      if (!confirm(`Import “${archive.name}” and stage it for restoration? Gateway data will be replaced on restart.`)) return {cancelled: true};
      await api('backups/import', {method: 'POST', headers: {'Content-Type': 'application/octet-stream', 'X-Backup-Passphrase': encodeURIComponent(passwordValue(form, 'passphrase')), 'X-Backup-Passphrase-Encoding': 'uri'}, body: archive}); return restoreResult();
    }, 'Verify & stage restore');
  }

  async function settingsView() {
    const settings = await api('settings'); const page = pageContainer('settings'); const form = node('form', {class: 'settings-form'});
    function settingsPanel(title, description) {const body = node('div', {class: 'panel-body'}, node('h2', {}, title), node('p', {class: 'description'}, description)); const panel = node('section', {class: 'panel'}, body); form.append(panel); return body;}
    const server = settingsPanel('Server and requests', 'Changes apply to new operations. Existing streams can finish.');
    formField(server, 'Listen address', 'listen_address', settings.listen_address, {required: true, placeholder: '0.0.0.0:8080', help: 'Use host:port. A listener change is applied only if the new address can be bound.'});
    const timing = node('div', {class: 'field-grid'}); server.append(timing);
    formField(timing, 'Health check interval (seconds)', 'health_interval_seconds', settings.health_interval_seconds, {type: 'number', required: true, min: 1, max: 86400, step: 1});
    formField(timing, 'Request timeout (seconds)', 'request_timeout_seconds', settings.request_timeout_seconds, {type: 'number', required: true, min: 1, max: 86400, step: 1});
    const logs = settingsPanel('Logs and statistics', 'Detailed request logs rotate on disk. Daily aggregates outlive detail retention.');
    const logGrid = node('div', {class: 'field-grid'}); logs.append(logGrid);
    formField(logGrid, 'Rotate detailed logs at (MiB)', 'log_rotation_mib', settings.log_rotation_bytes / 1048576, {type: 'number', required: true, min: 1 / 1024, max: 1048576, step: 'any'});
    formField(logGrid, 'Log generations to retain', 'log_generations', settings.log_generations, {type: 'number', required: true, min: 1, max: 100, step: 1});
    formField(logGrid, 'Detailed statistics retention (days)', 'statistics_retention_days', settings.statistics_retention_days, {type: 'number', required: true, min: 1, max: 36500, step: 1});
    const backups = settingsPanel('Automatic backups', 'Create a local snapshot each day and remove expired automatic backups.');
    check(backups, 'Enable daily automatic backups', 'auto_backup_enabled', settings.auto_backup_enabled);
    formField(backups, 'Backup retention (days)', 'backup_retention_days', settings.backup_retention_days, {type: 'number', required: true, min: 1, max: 36500, step: 1});
    const errorBox = notice('', 'error'); errorBox.hidden = true; const submit = node('button', {type: 'submit', class: 'button primary'}, 'Save settings'); form.append(errorBox, node('div', {class: 'form-actions'}, submit));
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (!form.reportValidity() || submit.disabled) return;
      const data = {...settings, listen_address: formValue(form, 'listen_address'), auto_backup_enabled: checkedValue(form, 'auto_backup_enabled'), log_rotation_bytes: Math.round(Number(formValue(form, 'log_rotation_mib')) * 1048576)};
      for (const key of ['health_interval_seconds', 'request_timeout_seconds', 'log_generations', 'statistics_retention_days', 'backup_retention_days']) data[key] = Number(formValue(form, key));
      submit.disabled = true; errorBox.hidden = true;
      try {await api('settings', {method: 'PUT', body: data}); if (data.listen_address !== settings.listen_address) {page.prepend(notice(`Listener changed to ${data.listen_address}. Open the gateway’s new address manually to continue; this page will not redirect automatically.`, 'success')); Object.assign(settings, data);} else {Object.assign(settings, data); toast('Settings saved.');}}
      catch (error) {if (error.status === 401) {await showAuth(false, 'Sign in to continue.'); return;} errorBox.textContent = error.message; errorBox.hidden = false;} finally {submit.disabled = false;}
    });
    page.append(form); return page;
  }

  const views = {dashboard: dashboardView, engines: enginesView, 'upstream-models': discoveryView, models: modelsView, keys: keysView, statistics: statisticsView, 'access-logs': () => logsView(false), 'audit-logs': () => logsView(true), backups: backupsView, admins: adminsView, settings: settingsView};
  window.addEventListener('hashchange', () => {if (state.admin) run(() => showPage(location.hash.slice(1) || 'dashboard'));});
  async function start() {
    try {const session = await api('session'); state.admin = session.admin; state.csrf = session.csrf_token; shell(); await showPage(location.hash.slice(1) || 'dashboard');}
    catch (error) {if (error.status === 401) await showAuth(location.pathname === '/setup'); else {app.replaceChildren(node('main', {id: 'main', class: 'initial-state'}, brand(), notice(error.message, 'error'), button('Try again', start)));}}
  }
  run(start);
})();

/**
 * TLS Downgrade & Cipher Suite Analyzer – Dashboard JavaScript
 */

let currentResults = [];
let charts = {};
let lastScanTargetId = null;

// ── Data Loading ─────────────────────────────────────────────

async function loadResults(autoOpenTargetId = null) {
    try {
        const resp = await fetch('/api/results');
        const data = await resp.json();
        currentResults = data.results || [];
        render();

        loadProfileResults();
        loadClientResults();
        loadDiscoveryResults();
        loadLabResults();
        loadStackResults();

        if (autoOpenTargetId) {
            const idx = currentResults.findIndex(r => {
                const key = `${r.host}_${r.port}`.replace(/\./g, '_');
                return key === autoOpenTargetId;
            });
            if (idx >= 0) {
                setTimeout(() => showDetail(idx), 400);
            }
        }
    } catch (e) {
        console.error('Failed to load results:', e);
    }
}

async function loadProfileResults() {
    try {
        const resp = await fetch('/api/profile-results');
        const data = await resp.json();
        renderProfileResults(data);
    } catch (e) {
        console.error('Failed to load profile results:', e);
    }
}

function renderProfileResults(data) {
    const section = document.getElementById('profileSection');
    const body = document.getElementById('profileBody');
    if (!data.devices || data.devices.length === 0) {
        section.style.display = 'none';
        return;
    }
    section.style.display = 'block';
    let html = '';

    // Stat cards: IoT vs Web comparison
    const hasComparison = (data.iot_count > 0 && data.web_count > 0);
    html += `<div class="row mb-3">`;
    html += _clientStatCard('IoT Devices', data.iot_count || 0, 'bi-cpu');
    html += _clientStatCard('Web Servers', data.web_count || 0, 'bi-globe');
    html += _clientStatCard('IoT Weak Selection', (data.iot_weak_selection_pct || 0) + '%', 'bi-exclamation-triangle', 'text-danger');
    html += _clientStatCard('Web Weak Selection', (data.web_weak_selection_pct || 0) + '%', 'bi-check-circle', 'text-success');
    html += `</div>`;

    // Comparison bar chart
    if (hasComparison) {
        html += `<div class="row mb-3"><div class="col-lg-6">`;
        html += `<canvas id="profileCompareChart" style="max-height:220px"></canvas>`;
        html += `</div><div class="col-lg-6">`;
        html += `<canvas id="profilePfsChart" style="max-height:220px"></canvas>`;
        html += `</div></div>`;
    }

    // Per-device results table
    html += `<h6 class="mt-3">Per-Device Cipher Selection</h6>`;
    html += `<table class="table table-sm table-dark table-hover"><thead><tr>`;
    html += `<th>Device</th><th>Type</th>`;
    html += `<th><span class="text-success">Modern</span></th>`;
    html += `<th><span class="text-warning">Mixed</span></th>`;
    html += `<th><span class="text-danger">Legacy</span></th>`;
    html += `<th>Pref?</th><th>Result</th>`;
    html += `</tr></thead><tbody>`;

    data.devices.forEach(d => {
        const fmtProfile = (p) => {
            if (!p || !p.connected) return `<span class="text-muted">Failed</span>`;
            const pfs = p.has_forward_secrecy ? ' <span class="badge bg-success bg-opacity-25 text-success" style="font-size:0.65rem">PFS</span>' : '';
            const aead = p.is_aead ? ' <span class="badge bg-info bg-opacity-25 text-info" style="font-size:0.65rem">AEAD</span>' : '';
            const gradeClass = {'A': 'text-success', 'B': 'text-info', 'C': 'text-warning', 'D': 'text-danger', 'F': 'text-danger'}[p.grade] || '';
            return `<span class="${gradeClass}">${p.cipher_name?.substring(0, 24) || '?'}</span>${pfs}${aead}<br><small class="text-muted">${p.tls_version}</small>`;
        };
        const pref = d.server_enforces_preference
            ? '<span class="text-success"><i class="bi bi-check-circle-fill"></i></span>'
            : '<span class="text-danger"><i class="bi bi-x-circle-fill"></i></span>';
        const weak = d.chose_weak_with_mixed
            ? '<span class="badge bg-danger">CHOSE WEAK</span>'
            : '<span class="badge bg-success">OK</span>';
        const typeIcon = d.device_type === 'iot' ? '<i class="bi bi-cpu"></i> IoT' : '<i class="bi bi-globe"></i> Web';

        html += `<tr>`;
        html += `<td><strong>${d.label}</strong><br><small class="text-muted">${d.host}:${d.port}</small></td>`;
        html += `<td>${typeIcon}</td>`;
        html += `<td>${fmtProfile(d.profiles?.modern)}</td>`;
        html += `<td>${fmtProfile(d.profiles?.mixed)}</td>`;
        html += `<td>${fmtProfile(d.profiles?.legacy)}</td>`;
        html += `<td>${pref}</td>`;
        html += `<td>${weak}</td>`;
        html += `</tr>`;
    });

    html += `</tbody></table>`;

    // Findings
    if (data.findings && data.findings.length > 0) {
        html += `<h6 class="mt-3">Findings</h6>`;
        data.findings.forEach(f => {
            const cls = f.includes('weak') || f.includes('WEAK') || f.includes('Weak') ? 'text-danger' : 'text-info';
            html += `<p class="${cls} small"><i class="bi bi-arrow-right"></i> ${f}</p>`;
        });
    }

    body.innerHTML = html;

    // Render comparison charts after DOM update
    if (hasComparison) {
        setTimeout(() => {
            _renderProfileCompareChart(data);
            _renderProfilePfsChart(data);
        }, 100);
    }
}

function _renderProfileCompareChart(data) {
    const ctx = document.getElementById('profileCompareChart');
    if (!ctx) return;
    new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Weak Cipher Selection %', 'Server Preference Enforced %'],
            datasets: [
                { label: 'IoT Devices', data: [data.iot_weak_selection_pct, data.iot_preference_enforced_pct], backgroundColor: '#e74c3c', borderRadius: 4 },
                { label: 'Web Servers', data: [data.web_weak_selection_pct, data.web_preference_enforced_pct], backgroundColor: '#2ecc71', borderRadius: 4 },
            ]
        },
        options: {
            indexAxis: 'y',
            scales: { x: { beginAtZero: true, max: 100, grid: { color: 'rgba(255,255,255,0.05)' } }, y: { grid: { display: false } } },
            plugins: { legend: { position: 'bottom', labels: { font: { size: 10 } } }, title: { display: true, text: 'IoT vs Web: Cipher Selection Behavior', font: { size: 12 } } },
        }
    });
}

function _renderProfilePfsChart(data) {
    const ctx = document.getElementById('profilePfsChart');
    if (!ctx) return;
    new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['IoT Devices', 'Web Servers'],
            datasets: [
                { label: 'PFS with Mixed Client %', data: [data.iot_pfs_with_mixed_pct, data.web_pfs_with_mixed_pct], backgroundColor: ['#e74c3c', '#2ecc71'], borderRadius: 4 },
            ]
        },
        options: {
            scales: { y: { beginAtZero: true, max: 100, grid: { color: 'rgba(255,255,255,0.05)' } }, x: { grid: { display: false } } },
            plugins: { legend: { display: false }, title: { display: true, text: 'Forward Secrecy Adoption (Mixed Client)', font: { size: 12 } } },
        }
    });
}

async function loadClientResults() {
    try {
        const resp = await fetch('/api/client-results');
        const data = await resp.json();
        renderClientTests(data);
    } catch (e) {
        console.error('Failed to load client results:', e);
    }
}

function renderClientTests(data) {
    const section = document.getElementById('clientTestSection');
    const body = document.getElementById('clientTestBody');

    const hasData = (data.client_test_report || data.mitm_test_report);
    if (!hasData) {
        section.style.display = 'none';
        return;
    }
    section.style.display = 'block';

    let html = '';

    // Malicious server results
    const srvReport = data.client_test_report;
    if (srvReport) {
        html += `<h6 class="text-warning">Mode A: Malicious Server (Sentinel Omission Test)</h6>`;
        html += `<div class="row mb-3">`;
        html += _clientStatCard('Total Connections', srvReport.total_client_connections || 0, 'bi-plug');
        html += _clientStatCard('Vulnerable (No Sentinel Check)', srvReport.clients_vulnerable_to_sentinel_omission || 0, 'bi-exclamation-triangle', 'text-danger');
        html += _clientStatCard('Protected', srvReport.clients_protected || 0, 'bi-shield-check', 'text-success');
        html += _clientStatCard('Sent SCSV', srvReport.clients_sending_scsv || 0, 'bi-lock');
        html += `</div>`;

        if (srvReport.findings && srvReport.findings.length > 0) {
            html += `<div class="mb-3">`;
            srvReport.findings.forEach(f => {
                const cls = f.includes('VULNERABLE') || f.includes('did NOT') ? 'text-danger' : 'text-info';
                html += `<p class="${cls}"><i class="bi bi-arrow-right"></i> ${f}</p>`;
            });
            html += `</div>`;
        }

        // Per-client results table
        const results = srvReport.server_test?.results || [];
        if (results.length > 0) {
            html += `<table class="table table-sm table-dark"><thead><tr>`;
            html += `<th>Client</th><th>Version Offered</th><th>Test</th><th>Sentinel Omitted</th><th>Accepted Downgrade</th><th>Vulnerable</th><th>Details</th>`;
            html += `</tr></thead><tbody>`;
            results.forEach(r => {
                const vulnCls = r.vulnerable ? 'text-danger fw-bold' : 'text-success';
                html += `<tr>`;
                html += `<td>${r.client_addr}</td>`;
                html += `<td>${r.client_version_offered}</td>`;
                html += `<td>${r.test_type}</td>`;
                html += `<td>${r.sentinel_omitted ? 'Yes' : 'No'}</td>`;
                html += `<td>${r.client_accepted_downgrade ? 'YES' : 'No'}</td>`;
                html += `<td class="${vulnCls}">${r.vulnerable ? 'VULNERABLE' : 'Protected'}</td>`;
                html += `<td><small>${r.details?.substring(0, 80) || ''}</small></td>`;
                html += `</tr>`;
            });
            html += `</tbody></table>`;
        }
    }

    // MITM proxy results
    const mitmReport = data.mitm_test_report;
    if (mitmReport) {
        html += `<h6 class="text-warning mt-3">Mode B: MITM Proxy (Version Downgrade + Sentinel Stripping)</h6>`;
        const mitm = mitmReport.mitm_test || {};
        html += `<div class="row mb-3">`;
        html += _clientStatCard('Connections Intercepted', mitm.total_connections || 0, 'bi-plug');
        html += _clientStatCard('Successful Downgrades', mitm.successful_downgrades || 0, 'bi-exclamation-triangle', 'text-danger');
        html += _clientStatCard('Blocked', mitm.blocked_downgrades || 0, 'bi-shield-check', 'text-success');
        html += `</div>`;

        if (mitmReport.findings && mitmReport.findings.length > 0) {
            html += `<div class="mb-3">`;
            mitmReport.findings.forEach(f => {
                const cls = f.includes('downgraded') ? 'text-danger' : 'text-info';
                html += `<p class="${cls}"><i class="bi bi-arrow-right"></i> ${f}</p>`;
            });
            html += `</div>`;
        }

        const events = mitm.events || [];
        if (events.length > 0) {
            html += `<table class="table table-sm table-dark"><thead><tr>`;
            html += `<th>Client</th><th>Original</th><th>Downgraded</th><th>Sentinel Stripped</th><th>Client Detected</th><th>Server Response</th>`;
            html += `</tr></thead><tbody>`;
            events.forEach(e => {
                html += `<tr>`;
                html += `<td>${e.client_addr}</td>`;
                html += `<td>${e.original_version}</td>`;
                html += `<td>${e.downgraded_version}</td>`;
                html += `<td>${e.sentinel_stripped ? 'YES' : 'No'}</td>`;
                html += `<td>${e.client_detected_downgrade ? 'Yes' : 'No'}</td>`;
                html += `<td>${e.server_response}</td>`;
                html += `</tr>`;
            });
            html += `</tbody></table>`;
        }
    }

    if (srvReport?.methodology_notes || mitmReport?.methodology_notes) {
        html += `<details class="mt-3"><summary class="text-muted">Methodology Notes</summary><ul class="mt-2">`;
        const notes = [...(srvReport?.methodology_notes || []), ...(mitmReport?.methodology_notes || [])];
        notes.forEach(n => { html += `<li class="text-muted small">${n}</li>`; });
        html += `</ul></details>`;
    }

    body.innerHTML = html;
}

// ── Network Discovery ─────────────────────────────────────────

async function loadDiscoveryResults() {
    try {
        const resp = await fetch('/api/discovery');
        const data = await resp.json();
        renderDiscovery(data);
    } catch (e) {
        console.error('Failed to load discovery results:', e);
    }
}

function renderDiscovery(data) {
    const section = document.getElementById('discoverySection');
    const devices = data.devices_found || [];
    if (devices.length === 0 && !data.scan_time) {
        section.style.display = 'none';
        return;
    }
    section.style.display = 'block';
    document.getElementById('discoveryCount').textContent = devices.length + ' device' + (devices.length !== 1 ? 's' : '');

    const tbody = document.querySelector('#discoveryTable tbody');
    tbody.innerHTML = devices.map(d => `
        <tr>
            <td><strong>${d.ip || d.host || '?'}</strong></td>
            <td>${d.port || '?'}</td>
            <td>${d.tls_version || d.highest_tls || '?'}</td>
            <td><code>${d.cert_subject || d.certificate?.subject || '—'}</code></td>
            <td>${d.device_type || d.classification || '—'}</td>
            <td>${d.banner_hint || '—'}</td>
        </tr>
    `).join('');
}

// ── Virtual Lab Report ───────────────────────────────────────

async function loadLabResults() {
    try {
        const resp = await fetch('/api/lab-results');
        const data = await resp.json();
        renderLabReport(data);
    } catch (e) {
        console.error('Failed to load lab results:', e);
    }
}

function renderLabReport(data) {
    const section = document.getElementById('labReportSection');
    const results = data.server_scan_results || [];
    if (results.length === 0 && !data.profiles_used) {
        section.style.display = 'none';
        return;
    }
    section.style.display = 'block';

    const statsDiv = document.getElementById('labStatCards');
    statsDiv.innerHTML = `
        ${_clientStatCard('Profiles Used', data.profiles_used || 0, 'bi-motherboard')}
        ${_clientStatCard('Devices Scanned', results.length, 'bi-cpu')}
        ${_clientStatCard('Duration', (data.duration_seconds || 0).toFixed(1) + 's', 'bi-clock')}
        ${_clientStatCard('Findings', (data.findings || []).length, 'bi-exclamation-triangle', 'text-warning')}
    `;

    const tbody = document.querySelector('#labResultsTable tbody');
    tbody.innerHTML = results.map(r => {
        const grade = r.overall_grade || '?';
        const gc = gradeToClass(grade);
        const versions = (r.version_scan?.versions || [])
            .filter(v => v.supported).map(v => v.version_name).join(', ') || '?';
        const risk = r.downgrade_report?.risk_level || r.overall_risk || '?';
        const riskCls = risk === 'Critical' || risk === 'High' ? 'text-danger' : risk === 'Medium' ? 'text-warning' : 'text-success';
        const sentinel = r.downgrade_report?.downgrade_sentinel || r.version_scan?.downgrade_sentinel;
        const sentinelHtml = sentinel
            ? (sentinel.sentinel_present
                ? '<span class="text-success"><i class="bi bi-check-circle-fill"></i></span>'
                : '<span class="text-danger"><i class="bi bi-x-circle-fill"></i></span>')
            : '<span class="text-muted">N/A</span>';

        return `<tr>
            <td><strong>${r.label || r.host || '?'}</strong><br><small class="text-muted">${r.host || ''}:${r.port || ''}</small></td>
            <td>${r.simulated ? '<span class="badge bg-info bg-opacity-25 text-info">Virtual</span>' : '<span class="badge bg-success bg-opacity-25 text-success">Real</span>'}</td>
            <td>${versions}</td>
            <td><span class="${riskCls}">${risk}</span></td>
            <td><span class="${gc} fw-bold">${grade}</span></td>
            <td>${sentinelHtml}</td>
        </tr>`;
    }).join('');

    const findingsDiv = document.getElementById('labFindings');
    const findings = data.findings || [];
    if (findings.length > 0) {
        findingsDiv.innerHTML = `
            <div class="card"><div class="card-header bg-dark">Lab Findings</div>
            <div class="card-body">${findings.map(f => {
                const cls = f.includes('VULNERABLE') || f.includes('weak') || f.includes('Critical') ? 'text-danger' : 'text-info';
                return `<p class="${cls} small mb-1"><i class="bi bi-arrow-right"></i> ${f}</p>`;
            }).join('')}</div></div>`;
    } else {
        findingsDiv.innerHTML = '';
    }
}

// ── Automated Stack Test Results ─────────────────────────────

async function loadStackResults() {
    try {
        const resp = await fetch('/api/stack-results');
        const data = await resp.json();
        renderStackTests(data);
    } catch (e) {
        console.error('Failed to load stack results:', e);
    }
}

function renderStackTests(data) {
    const section = document.getElementById('stackTestSection');
    const stacks = data.stack_reports || data.stacks || [];
    if (stacks.length === 0 && !data.stacks_tested) {
        section.style.display = 'none';
        return;
    }
    section.style.display = 'block';

    const statsDiv = document.getElementById('stackStatCards');
    statsDiv.innerHTML = `
        ${_clientStatCard('Stacks Tested', data.stacks_tested || stacks.length, 'bi-layers')}
        ${_clientStatCard('Vulnerable', data.stacks_vulnerable || 0, 'bi-exclamation-triangle', 'text-danger')}
        ${_clientStatCard('Protected', data.stacks_protected || 0, 'bi-shield-check', 'text-success')}
        ${_clientStatCard('Duration', (data.duration_seconds || 0).toFixed(1) + 's', 'bi-clock')}
    `;

    const tbody = document.querySelector('#stackTestTable tbody');
    tbody.innerHTML = stacks.map(s => {
        const tests = s.test_results || s.scenarios || [];
        const scenarioResult = (scenario) => {
            const sc = tests.find(x =>
                x.scenario === scenario || x.downgrade_to === scenario
            );
            if (!sc) return '<span class="text-muted">—</span>';
            if (sc.sentinel_detected || sc.detected) {
                return '<span class="text-success"><i class="bi bi-shield-check"></i> Detected</span>';
            }
            return '<span class="text-danger"><i class="bi bi-x-circle"></i> Missed</span>';
        };

        const vulnerable = s.overall_vulnerable || s.vulnerable;
        const verdictCls = vulnerable ? 'text-danger fw-bold' : 'text-success';
        const verdict = vulnerable ? 'VULNERABLE' : 'Protected';
        const rootCauses = (s.root_causes || []).join(', ') || s.root_cause || '—';
        const stackName = s.stack?.name || s.stack_name || s.name || '?';
        const stackLib = s.stack?.library || s.tls_library || '';

        return `<tr>
            <td><strong>${stackName}</strong><br><small class="text-muted">${stackLib}</small></td>
            <td>${scenarioResult('TLSv1.2')}</td>
            <td>${scenarioResult('TLSv1.1')}</td>
            <td>${scenarioResult('TLSv1.0')}</td>
            <td><code class="small">${rootCauses}</code></td>
            <td><span class="${verdictCls}">${verdict}</span></td>
        </tr>`;
    }).join('');
}

function _clientStatCard(label, value, icon, colorClass = '') {
    return `<div class="col-md-3"><div class="card bg-dark border-secondary">
        <div class="card-body text-center">
            <i class="bi ${icon} fs-3 ${colorClass}"></i>
            <h4 class="${colorClass}">${value}</h4>
            <small class="text-muted">${label}</small>
        </div></div></div>`;
}

let selectedScanType = null;
let lastCompletedScanType = null;
let scanPollTimer = null;

function selectScanType(type) {
    selectedScanType = type;

    document.querySelectorAll('.scan-type-card').forEach(c => {
        c.classList.remove('border-primary');
        c.classList.add('border-secondary');
    });

    const idMap = {
        server: 'scanTypeServer', lab: 'scanTypeLab', stacks: 'scanTypeStacks',
        profiles: 'scanTypeProfiles', discovery: 'scanTypeDiscovery',
        client_malicious: 'scanTypeClient_malicious', client_mitm: 'scanTypeClient_mitm',
        pdf: 'scanTypePdf',
    };
    const card = document.getElementById(idMap[type]);
    if (card) {
        card.classList.remove('border-secondary');
        card.classList.add('border-primary');
    }

    document.querySelectorAll('.scan-options').forEach(el => el.style.display = 'none');
    const optionsMap = {
        server: 'serverOptions',
        discovery: 'discoveryOptions',
        client_malicious: 'clientMaliciousOptions',
        client_mitm: 'clientMitmOptions',
    };
    if (optionsMap[type]) {
        document.getElementById(optionsMap[type]).style.display = 'block';
    }

    document.getElementById('scanStartBtn').disabled = false;
}

async function startScan() {
    if (!selectedScanType) return;

    const payload = { scan_type: selectedScanType };

    if (selectedScanType === 'server') {
        const host = document.getElementById('scanHost').value.trim();
        if (!host) { alert('Please enter a host/IP address.'); return; }
        payload.host = host;
        payload.port = parseInt(document.getElementById('scanPort').value) || 443;
        payload.label = document.getElementById('scanLabel').value.trim() || `${host}:${payload.port}`;
    } else if (selectedScanType === 'discovery') {
        const subnet = document.getElementById('scanSubnet').value.trim();
        if (!subnet) { alert('Please enter a subnet (e.g. 192.168.1.0/24).'); return; }
        payload.subnet = subnet;
        payload.ports = document.getElementById('scanDiscPorts').value.trim();
        payload.timeout = parseFloat(document.getElementById('scanDiscTimeout').value) || 2;
    } else if (selectedScanType === 'client_malicious') {
        payload.port = parseInt(document.getElementById('scanMalPort').value) || 4433;
        payload.duration = parseInt(document.getElementById('scanMalDuration').value) || 30;
    } else if (selectedScanType === 'client_mitm') {
        const target = document.getElementById('scanMitmTarget').value.trim();
        if (!target) { alert('Please enter a target host.'); return; }
        payload.target_host = target;
        payload.target_port = parseInt(document.getElementById('scanMitmTargetPort').value) || 443;
        payload.proxy_port = parseInt(document.getElementById('scanMitmProxyPort').value) || 8443;
        payload.downgrade_to = document.getElementById('scanMitmDowngrade').value;
        payload.duration = parseInt(document.getElementById('scanMitmDuration').value) || 30;
    }

    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();

        if (resp.status === 409) {
            alert(data.error || 'A scan is already running.');
            return;
        }
        if (!resp.ok) {
            alert(data.error || 'Failed to start scan.');
            return;
        }

        lastCompletedScanType = selectedScanType;
        document.getElementById('scanStep1').style.display = 'none';
        document.getElementById('scanStep2').style.display = 'block';
        document.getElementById('scanStartBtn').style.display = 'none';
        document.getElementById('scanCancelBtn').style.display = 'none';

        const typeNames = {
            server: 'Server Scan',
            lab: 'Virtual IoT Lab',
            stacks: 'Client Stack Test',
            profiles: 'Cipher Preference Experiment',
            discovery: 'Network Discovery',
            client_malicious: 'Malicious Server (Sentinel Omission)',
            client_mitm: 'MITM Proxy (Version Downgrade)',
            pdf: 'PDF Report Generation',
        };
        document.getElementById('scanStatusTitle').textContent = `Running ${typeNames[selectedScanType] || 'Scan'}...`;

        const subMap = {
            server: payload.host + ':' + payload.port,
            discovery: 'Subnet: ' + payload.subnet,
            client_malicious: 'Listening on port ' + payload.port + ' for ' + payload.duration + 's',
            client_mitm: 'Proxying to ' + payload.target_host + ':' + payload.target_port,
            pdf: 'Compiling results into PDF...',
        };
        document.getElementById('scanStatusSub').textContent = subMap[selectedScanType] || 'This may take 1-2 minutes';

        pollScanStatus();
    } catch (e) {
        alert('Failed to start scan: ' + e.message);
    }
}

function pollScanStatus() {
    if (scanPollTimer) clearInterval(scanPollTimer);

    scanPollTimer = setInterval(async () => {
        try {
            const resp = await fetch('/api/scan/status');
            const state = await resp.json();

            const bar = document.getElementById('scanProgressBar');
            bar.style.width = state.percent + '%';

            const logDiv = document.getElementById('scanLog');
            logDiv.innerHTML = state.progress.map(m =>
                `<div class="text-light" style="opacity:0.85"><span class="text-muted">&gt;</span> ${m}</div>`
            ).join('');
            logDiv.scrollTop = logDiv.scrollHeight;

            if (state.status === 'done') {
                clearInterval(scanPollTimer);
                scanPollTimer = null;

                if (state.result_summary?.target_id) {
                    lastScanTargetId = state.result_summary.target_id;
                }

                bar.classList.remove('progress-bar-animated', 'progress-bar-striped');
                bar.classList.add('bg-success');
                bar.style.width = '100%';

                document.getElementById('scanStatusIcon').innerHTML =
                    '<i class="bi bi-check-circle-fill text-success" style="font-size:3rem"></i>';
                document.getElementById('scanStatusTitle').textContent = 'Scan Complete!';
                document.getElementById('scanStatusSub').textContent = '';

                let summaryHtml = '<div class="alert alert-success d-flex align-items-center gap-2">' +
                    '<i class="bi bi-check-circle-fill"></i> Scan finished successfully.';
                if (state.result_summary) {
                    const s = state.result_summary;
                    if (s.grade) summaryHtml += ` Grade: <strong>${s.grade}</strong>, Risk: <strong>${s.risk}</strong>.`;
                    if (s.profiles !== undefined) summaryHtml += ` ${s.profiles} profiles, ${s.findings} findings.`;
                    if (s.tested) summaryHtml += ` ${s.vulnerable}/${s.tested} stacks vulnerable.`;
                    if (s.devices !== undefined) summaryHtml += ` ${s.devices} devices tested.`;
                    if (s.devices_found !== undefined) summaryHtml += ` ${s.devices_found} devices found on ${s.subnet}.`;
                    if (s.connections !== undefined) summaryHtml += ` ${s.connections} connections, ${s.vulnerable} vulnerable, ${s.protected} protected.`;
                    if (s.pdf_path) summaryHtml += ` PDF (${s.size_kb} KB) ready. <a href="/api/pdf" class="btn btn-sm btn-outline-light ms-2" download><i class="bi bi-download"></i> Download PDF</a>`;
                }
                summaryHtml += '</div>';
                document.getElementById('scanDoneSummary').innerHTML = summaryHtml;
                document.getElementById('scanDoneSummary').style.display = 'block';
                document.getElementById('scanDoneBtn').style.display = 'inline-block';

            } else if (state.status === 'error') {
                clearInterval(scanPollTimer);
                scanPollTimer = null;

                bar.classList.remove('progress-bar-animated', 'progress-bar-striped');
                bar.classList.add('bg-danger');

                document.getElementById('scanStatusIcon').innerHTML =
                    '<i class="bi bi-x-circle-fill text-danger" style="font-size:3rem"></i>';
                document.getElementById('scanStatusTitle').textContent = 'Scan Failed';
                document.getElementById('scanStatusSub').textContent = state.error || 'Unknown error';

                document.getElementById('scanDoneSummary').innerHTML =
                    `<div class="alert alert-danger"><i class="bi bi-x-circle-fill"></i> ${state.error || 'Scan failed'}</div>`;
                document.getElementById('scanDoneSummary').style.display = 'block';
                document.getElementById('scanDoneBtn').style.display = 'inline-block';
                document.getElementById('scanDoneBtn').textContent = 'Close';
                document.getElementById('scanDoneBtn').className = 'btn btn-secondary';
            }
        } catch (e) {
            console.error('Poll error:', e);
        }
    }, 1500);
}

function scanDoneClose() {
    if (scanPollTimer) { clearInterval(scanPollTimer); scanPollTimer = null; }
    const targetId = lastScanTargetId;
    const scanType = lastCompletedScanType;
    bootstrap.Modal.getInstance(document.getElementById('scanModal')).hide();
    resetScanModal();

    const sectionMap = {
        lab: 'labReportSection',
        stacks: 'stackTestSection',
        profiles: 'profileSection',
        discovery: 'discoverySection',
        client_malicious: 'clientTestSection',
        client_mitm: 'clientTestSection',
    };

    if (scanType === 'server' && targetId) {
        loadResults(targetId);
    } else if (sectionMap[scanType]) {
        loadResults().then(() => {
            setTimeout(() => {
                const el = document.getElementById(sectionMap[scanType]);
                if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 500);
        });
    } else {
        loadResults();
    }
}

function resetScanModal() {
    selectedScanType = null;
    lastCompletedScanType = null;
    document.getElementById('scanStep1').style.display = 'block';
    document.getElementById('scanStep2').style.display = 'none';
    document.getElementById('scanStartBtn').style.display = 'inline-block';
    document.getElementById('scanStartBtn').disabled = true;
    document.getElementById('scanCancelBtn').style.display = 'inline-block';
    document.getElementById('scanDoneBtn').style.display = 'none';
    document.getElementById('scanDoneBtn').textContent = 'Done - View Results';
    document.getElementById('scanDoneBtn').className = 'btn btn-success';
    document.getElementById('scanDoneSummary').style.display = 'none';
    document.getElementById('scanLog').innerHTML = '';
    document.getElementById('scanProgressBar').style.width = '0%';
    document.getElementById('scanProgressBar').className = 'progress-bar progress-bar-striped progress-bar-animated';
    document.getElementById('scanStatusIcon').innerHTML =
        '<div class="spinner-border text-primary" style="width:3rem;height:3rem" role="status"></div>';
    document.querySelectorAll('.scan-options').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.scan-type-card').forEach(c => {
        c.classList.remove('border-primary');
        c.classList.add('border-secondary');
    });
}

document.getElementById('scanModal')?.addEventListener('hidden.bs.modal', () => {
    if (scanPollTimer) { clearInterval(scanPollTimer); scanPollTimer = null; }
    resetScanModal();
});

// ── Rendering ────────────────────────────────────────────────

function render() {
    renderSummary();
    renderCharts();
    renderDeviceCards();
}

function renderSummary() {
    document.getElementById('totalDevices').textContent = currentResults.length;

    const vulnCount = currentResults.filter(r =>
        r.downgrade_report && r.downgrade_report.vulnerable_to_downgrade
    ).length;
    document.getElementById('vulnerableCount').textContent = vulnCount;

    const tls13 = currentResults.filter(r => {
        const vs = r.version_scan;
        if (!vs) return false;
        return (vs.versions || []).some(v => v.version_name === 'TLS 1.3' && v.supported);
    }).length;
    document.getElementById('tls13Count').textContent = tls13;

    const scores = currentResults
        .map(r => r.downgrade_report?.risk_score ?? 0)
        .filter(s => s > 0);
    const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    document.getElementById('avgRisk').textContent = avg;
}

function renderCharts() {
    renderRiskChart();
    renderVersionChart();
    renderVulnChart();
}

function renderRiskChart() {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Minimal: 0 };
    currentResults.forEach(r => {
        const level = r.downgrade_report?.risk_level || r.overall_risk || 'Unknown';
        if (counts[level] !== undefined) counts[level]++;
    });

    const ctx = document.getElementById('riskChart').getContext('2d');
    if (charts.risk) charts.risk.destroy();

    charts.risk = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(counts),
            datasets: [{
                data: Object.values(counts),
                backgroundColor: ['#e74c3c', '#e67e22', '#f39c12', '#2ecc71', '#27ae60'],
                borderWidth: 0,
                hoverOffset: 8,
            }],
        },
        options: {
            cutout: '65%',
            plugins: {
                legend: { position: 'bottom', labels: { padding: 12, usePointStyle: true, pointStyleWidth: 10, font: { size: 11 } } },
            },
        },
    });
}

function renderVersionChart() {
    const versions = ['SSLv3', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'];
    const supported = versions.map(vn =>
        currentResults.filter(r =>
            (r.version_scan?.versions || []).some(v => v.version_name === vn && v.supported)
        ).length
    );

    const ctx = document.getElementById('versionChart').getContext('2d');
    if (charts.version) charts.version.destroy();

    charts.version = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: versions,
            datasets: [{
                label: 'Devices Supporting',
                data: supported,
                backgroundColor: ['#e74c3c', '#e67e22', '#f39c12', '#3498db', '#2ecc71'],
                borderRadius: 6,
                borderSkipped: false,
            }],
        },
        options: {
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { grid: { display: false }, ticks: { font: { size: 10 } } },
            },
            plugins: { legend: { display: false } },
        },
    });
}

function renderVulnChart() {
    const flags = {
        'No SCSV':    0, 'No Sentinel': 0, 'Version Intol.': 0,
        'RC4':        0, '3DES':        0, 'NULL Cipher':    0,
        'Export':     0, 'CBC Only':    0, 'No PFS':         0,
    };

    currentResults.forEach(r => {
        const dr = r.downgrade_report;
        const cs = r.cipher_scan;
        if (dr) {
            if (dr.fallback_scsv && !dr.fallback_scsv.scsv_supported) flags['No SCSV']++;
            if (dr.downgrade_sentinel && !dr.downgrade_sentinel.sentinel_present) flags['No Sentinel']++;
            if (dr.version_intolerance?.intolerant) flags['Version Intol.']++;
        }
        if (cs) {
            if (cs.has_rc4) flags['RC4']++;
            if (cs.has_3des) flags['3DES']++;
            if (cs.has_null_cipher) flags['NULL Cipher']++;
            if (cs.has_export) flags['Export']++;
            if (!cs.forward_secrecy_support) flags['No PFS']++;
            if (cs.has_cbc && !cs.aead_support) flags['CBC Only']++;
        }
    });

    const ctx = document.getElementById('vulnChart').getContext('2d');
    if (charts.vuln) charts.vuln.destroy();

    charts.vuln = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: Object.keys(flags),
            datasets: [{
                label: 'Devices Affected',
                data: Object.values(flags),
                backgroundColor: 'rgba(231, 76, 60, 0.15)',
                borderColor: '#e74c3c',
                borderWidth: 2,
                pointBackgroundColor: '#e74c3c',
                pointRadius: 4,
            }],
        },
        options: {
            scales: {
                r: {
                    beginAtZero: true,
                    ticks: { stepSize: 1, font: { size: 9 }, backdropColor: 'transparent' },
                    grid: { color: 'rgba(255,255,255,0.08)' },
                    pointLabels: { font: { size: 9 } },
                },
            },
            plugins: { legend: { display: false } },
        },
    });
}

// ── Device Cards ─────────────────────────────────────────────

function renderDeviceCards() {
    const container = document.getElementById('deviceCards');
    document.getElementById('emptyState')?.remove();

    if (currentResults.length === 0) {
        container.innerHTML = `<div class="col-12 text-center text-muted py-5">
            <i class="bi bi-inbox display-1"></i>
            <p class="mt-3">No scan results yet. Click <strong>New Scan</strong> to get started.</p>
        </div>`;
        return;
    }

    const fiveMinAgo = Date.now() - 5 * 60 * 1000;

    container.innerHTML = currentResults.map((r, i) => {
        const grade = r.overall_grade || r.cipher_scan?.overall_grade || '?';
        const risk = r.overall_risk || r.downgrade_report?.risk_level || 'Unknown';
        const riskClass = risk.toLowerCase();
        const gradeClass = gradeToClass(grade);
        const versions = (r.version_scan?.versions || []);
        const versionPills = versions.map(v =>
            `<span class="version-pill ${v.supported ? 'version-supported' : 'version-unsupported'}">${v.supported ? '<i class="bi bi-check-circle-fill"></i>' : '<i class="bi bi-x-circle"></i>'} ${v.version_name}</span>`
        ).join(' ');
        const cipherCount = (r.cipher_scan?.accepted_ciphers || []).length;
        const findingCount = (r.downgrade_report?.findings || []).length;
        const scanMs = r.scan_duration_ms ? (r.scan_duration_ms / 1000).toFixed(1) : '?';

        const isNew = r.scan_time && new Date(r.scan_time).getTime() > fiveMinAgo;
        const newBadge = isNew ? '<span class="badge bg-success ms-2" style="font-size:0.6rem;vertical-align:middle">NEW</span>' : '';

        const unreachable = r.reachable === false;
        const unreachableBadge = unreachable
            ? '<span class="badge bg-warning text-dark ms-2" style="font-size:0.6rem;vertical-align:middle"><i class="bi bi-exclamation-triangle-fill"></i> Unreachable</span>'
            : '';

        const cardOpacity = unreachable ? 'opacity: 0.7;' : '';
        const cardBorder = isNew ? 'border: 1px solid rgba(25,135,84,0.5);' : '';

        return `
        <div class="col-xl-6 fade-in" style="animation-delay: ${Math.min(i, 10) * 0.05}s">
            <div class="card device-card" data-detail-index="${i}" style="cursor:pointer;${cardOpacity}${cardBorder}">
                <div class="card-body">
                    <div class="d-flex align-items-start gap-3">
                        <div class="grade-badge ${gradeClass}">${grade}</div>
                        <div class="flex-grow-1">
                            <div class="d-flex justify-content-between align-items-start">
                                <div>
                                    <h6 class="mb-1 fw-bold">${r.label || r.host}${newBadge}${unreachableBadge}</h6>
                                    <small class="text-muted">${r.host}:${r.port}</small>
                                </div>
                                <span class="risk-badge risk-${riskClass}">${risk}</span>
                            </div>
                            <div class="mt-2 d-flex flex-wrap gap-1">
                                ${versionPills}
                            </div>
                            <div class="mt-2 d-flex gap-3">
                                <small class="text-muted"><i class="bi bi-lock"></i> ${cipherCount} ciphers</small>
                                <small class="text-muted"><i class="bi bi-exclamation-diamond"></i> ${findingCount} findings</small>
                                <small class="text-muted"><i class="bi bi-clock"></i> ${scanMs}s</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>`;
    }).join('');

    container.querySelectorAll('[data-detail-index]').forEach(card => {
        card.addEventListener('click', () => showDetail(parseInt(card.dataset.detailIndex)));
    });
}

function gradeToClass(grade) {
    const map = { 'A+': 'grade-a-plus', 'A': 'grade-a', 'B': 'grade-b', 'C': 'grade-c', 'D': 'grade-d', 'F': 'grade-f' };
    return map[grade] || 'grade-f';
}

// ── Detail Modal ─────────────────────────────────────────────

function showDetail(index) {
    const r = currentResults[index];
    document.getElementById('detailTitle').textContent = `${r.label || r.host} — ${r.host}:${r.port}`;

    const body = document.getElementById('detailBody');
    body.innerHTML = buildDetailHTML(r);

    new bootstrap.Modal(document.getElementById('detailModal')).show();
}

function buildDetailHTML(r) {
    let html = '';

    // Risk overview
    const dr = r.downgrade_report || {};
    const riskScore = dr.risk_score || 0;
    const riskLevel = dr.risk_level || r.overall_risk || 'Unknown';
    const riskClass = riskLevel.toLowerCase();

    html += `
    <div class="mb-4">
        <h6 class="text-muted text-uppercase small mb-3">Risk Assessment</h6>
        <div class="d-flex align-items-center gap-3 mb-2">
            <span class="risk-badge risk-${riskClass}" style="font-size:0.9rem; padding:5px 14px;">${riskLevel}</span>
            <span class="fw-bold">${riskScore}/100</span>
        </div>
        <div class="risk-meter">
            <div class="risk-needle" style="left: ${riskScore}%"></div>
        </div>
    </div>`;

    // Downgrade protection checks
    html += `<h6 class="text-muted text-uppercase small mb-3">Downgrade Protection Checks</h6>`;

    const scsv = dr.fallback_scsv;
    if (scsv) {
        const pass = scsv.scsv_supported;
        html += protectionCheck(pass, 'TLS_FALLBACK_SCSV (RFC 7507)', scsv.details);
    }

    const sentinel = dr.downgrade_sentinel || r.version_scan?.downgrade_sentinel;
    if (sentinel) {
        const pass = sentinel.sentinel_present;
        html += protectionCheck(pass, 'TLS 1.3 Downgrade Sentinel (RFC 8446)', sentinel.details);
    }

    const vi = dr.version_intolerance;
    if (vi) {
        const pass = !vi.intolerant;
        html += protectionCheck(pass, 'Version Tolerance', vi.details);
    }

    // Version support table
    const versions = r.version_scan?.versions || [];
    if (versions.length) {
        html += `
        <h6 class="text-muted text-uppercase small mt-4 mb-3">TLS Version Support</h6>
        <table class="table table-sm table-hover">
            <thead><tr><th>Version</th><th>Status</th><th>Negotiated Cipher</th><th>Latency</th></tr></thead>
            <tbody>`;
        versions.forEach(v => {
            const icon = v.supported
                ? '<span class="text-success"><i class="bi bi-check-circle-fill"></i> Supported</span>'
                : '<span class="text-muted"><i class="bi bi-x-circle"></i> Not supported</span>';
            html += `<tr><td><strong>${v.version_name}</strong></td><td>${icon}</td><td><code>${v.negotiated_cipher || '—'}</code></td><td>${v.latency_ms || 0} ms</td></tr>`;
        });
        html += '</tbody></table>';
    }

    // Cipher suites
    const ciphers = r.cipher_scan?.accepted_ciphers || [];
    if (ciphers.length) {
        const pref = r.cipher_scan?.server_preference_enforced;
        const pfs = r.cipher_scan?.forward_secrecy_support;
        const aead = r.cipher_scan?.aead_support;

        html += `
        <h6 class="text-muted text-uppercase small mt-4 mb-2">Accepted Cipher Suites (${r.cipher_scan?.tls_version_tested || '?'})</h6>
        <div class="d-flex gap-3 mb-3">
            <small>${featureBadge(pref, 'Server Preference')}</small>
            <small>${featureBadge(pfs, 'Forward Secrecy')}</small>
            <small>${featureBadge(aead, 'AEAD Ciphers')}</small>
        </div>`;

        ciphers.forEach(c => {
            const gc = gradeToClass(c.grade);
            html += `
            <div class="cipher-row">
                <div class="cipher-grade ${gc}" style="color:#fff">${c.grade}</div>
                <div class="flex-grow-1">
                    <div><strong>${c.name}</strong></div>
                    <small class="text-muted">${c.kex} / ${c.enc} / ${c.mac}${c.notes ? ' — ' + c.notes : ''}</small>
                </div>
                <span class="badge" style="background:${c.color}20; color:${c.color}">${c.security}</span>
            </div>`;
        });

        // TLS 1.2 ciphers if available
        const tls12ciphers = r.cipher_scan?.tls12_ciphers || [];
        if (tls12ciphers.length) {
            html += `<h6 class="text-muted text-uppercase small mt-4 mb-2">TLS 1.2 Cipher Suites</h6>`;
            tls12ciphers.forEach(c => {
                const gc = gradeToClass(c.grade);
                html += `
                <div class="cipher-row">
                    <div class="cipher-grade ${gc}" style="color:#fff">${c.grade}</div>
                    <div class="flex-grow-1">
                        <div><strong>${c.name}</strong></div>
                        <small class="text-muted">${c.kex} / ${c.enc} / ${c.mac}${c.notes ? ' — ' + c.notes : ''}</small>
                    </div>
                    <span class="badge" style="background:${c.color}20; color:${c.color}">${c.security}</span>
                </div>`;
            });
        }
    }

    // Attack flow diagram
    if (dr.vulnerable_to_downgrade) {
        const lowestVer = r.version_scan?.lowest_supported || 'TLS 1.0';
        html += `
        <h6 class="text-muted text-uppercase small mt-4 mb-3"><i class="bi bi-diagram-3"></i> Downgrade Attack Flow</h6>
        <div class="attack-flow bg-dark rounded p-3">
            <div class="attack-node bg-primary bg-opacity-25 text-primary">Client<br><small>TLS 1.3 Hello</small></div>
            <div class="attack-arrow"><i class="bi bi-arrow-right"></i></div>
            <div class="attack-node bg-danger bg-opacity-25 text-danger">MITM Attacker<br><small>Rewrites to ${lowestVer}</small></div>
            <div class="attack-arrow"><i class="bi bi-arrow-right"></i></div>
            <div class="attack-node bg-warning bg-opacity-25 text-warning">${r.label}<br><small>Accepts ${lowestVer}</small></div>
        </div>
        <small class="text-muted mt-2 d-block">An active attacker can intercept and rewrite the ClientHello version to force a weaker protocol.</small>`;
    }

    // Findings & recommendations
    const findings = dr.findings || [];
    const recs = dr.recommendations || [];

    if (findings.length) {
        html += `<h6 class="text-muted text-uppercase small mt-4 mb-3">Findings</h6>`;
        findings.forEach(f => {
            html += `
            <div class="finding-item">
                <div class="finding-icon bg-danger bg-opacity-10 text-danger"><i class="bi bi-exclamation"></i></div>
                <span>${f}</span>
            </div>`;
        });
    }

    if (recs.length) {
        html += `<h6 class="text-muted text-uppercase small mt-4 mb-3">Recommendations</h6>`;
        recs.forEach(rec => {
            html += `
            <div class="finding-item">
                <div class="finding-icon bg-success bg-opacity-10 text-success"><i class="bi bi-arrow-right"></i></div>
                <span>${rec}</span>
            </div>`;
        });
    }

    return html;
}

function protectionCheck(pass, label, details) {
    const cls = pass ? 'check-pass' : 'check-fail';
    const icon = pass
        ? '<i class="bi bi-check-circle-fill text-success check-icon"></i>'
        : '<i class="bi bi-x-circle-fill text-danger check-icon"></i>';
    return `
    <div class="protection-check ${cls}">
        ${icon}
        <div>
            <div class="fw-bold">${label}</div>
            <small class="text-muted">${details || ''}</small>
        </div>
    </div>`;
}

function featureBadge(enabled, label) {
    const color = enabled ? 'success' : 'secondary';
    const icon = enabled ? 'check-circle-fill' : 'x-circle';
    return `<span class="badge bg-${color} bg-opacity-10 text-${color}"><i class="bi bi-${icon}"></i> ${label}</span>`;
}

// ── Init ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadResults();

    document.getElementById('refreshBtn')?.addEventListener('click', () => loadResults());
    document.getElementById('scanStartBtn')?.addEventListener('click', () => startScan());
    document.getElementById('scanDoneBtn')?.addEventListener('click', () => scanDoneClose());

    document.querySelectorAll('.scan-type-card[data-scan-type]').forEach(card => {
        card.addEventListener('click', () => selectScanType(card.dataset.scanType));
    });
});

/* =========================================================
   Centralized — app.js
   Chart.js initialization + CVE lookup modal
   ========================================================= */

/* ── Chart defaults ─────────────────────────────────────── */

Chart.defaults.color = '#adb5bd';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";

/* Detect glassmorphic mode — used to tweak chart rendering */
const _isGlass = () => document.documentElement.dataset.glass === '1';

/* Convert solid hex colors to semi-transparent rgba for glass style */
function glassColors(colors) {
  if (!_isGlass()) return colors;
  return colors.map(c => {
    if (typeof c === 'string' && c.startsWith('#') && c.length >= 7) {
      const r = parseInt(c.slice(1,3), 16);
      const g = parseInt(c.slice(3,5), 16);
      const b = parseInt(c.slice(5,7), 16);
      return `rgba(${r},${g},${b},0.78)`;
    }
    return c;
  });
}

/* Chart.js glass tooltip defaults */
function applyGlassChartDefaults() {
  if (!_isGlass()) return;
  Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(10,12,18,0.72)';
  Chart.defaults.plugins.tooltip.borderColor     = 'rgba(255,255,255,0.16)';
  Chart.defaults.plugins.tooltip.borderWidth     = 1;
  Chart.defaults.plugins.tooltip.titleColor      = '#fff';
  Chart.defaults.plugins.tooltip.bodyColor       = '#cbd3da';
  Chart.defaults.plugins.tooltip.padding         = 10;
  Chart.defaults.plugins.tooltip.cornerRadius    = 8;
}
applyGlassChartDefaults();

const SEV_COLORS = {
  CRITICAL: '#dc3545',
  HIGH:     '#fd7e14',
  MEDIUM:   '#ffc107',
  LOW:      '#0dcaf0',
  INFO:     '#6c757d',
  UNKNOWN:  '#495057',
};

/* ── Dashboard charts ───────────────────────────────────── */

function initDashboardCharts(sevData, svcLabels, svcValues, monthLabels, monthValues) {
  // Severity doughnut
  const sevCtx = document.getElementById('sevChart');
  if (sevCtx) {
    const glass = _isGlass();
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: sevData.labels,
        datasets: [{
          data:            sevData.values,
          backgroundColor: glassColors(sevData.colors),
          borderWidth:     glass ? 0 : 2,
          borderColor:     glass ? 'transparent' : '#1a1d23',
          hoverOffset:     glass ? 10 : 4,
          hoverBorderWidth: glass ? 2 : 2,
          hoverBorderColor: glass ? 'rgba(255,255,255,0.45)' : '#fff',
        }],
      },
      options: {
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#adb5bd', font: { size: 12 }, padding: 12, usePointStyle: true, pointStyleWidth: 10 },
          },
        },
        cutout: glass ? '70%' : '68%',
      },
    });
  }

  // Services bar
  const svcCtx = document.getElementById('svcChart');
  if (svcCtx) {
    const glass = _isGlass();
    new Chart(svcCtx, {
      type: 'bar',
      data: {
        labels: svcLabels,
        datasets: [{
          label: 'Ports',
          data: svcValues,
          backgroundColor: glass
            ? svcValues.map(() => 'rgba(13,110,253,0.50)')
            : 'rgba(13,110,253,0.72)',
          borderColor:  glass ? 'rgba(13,110,253,0.80)' : undefined,
          borderWidth:  glass ? 1 : 0,
          borderRadius: glass ? 6 : 5,
          hoverBackgroundColor: glass ? 'rgba(13,110,253,0.72)' : 'rgba(13,110,253,0.85)',
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#adb5bd' }, grid: { display: false } },
          y: {
            ticks: { color: '#adb5bd', stepSize: 1 },
            grid:  { color: glass ? 'rgba(255,255,255,0.04)' : 'rgba(255,255,255,0.05)' },
          },
        },
      },
    });
  }

  // Monthly line chart
  const monthCtx = document.getElementById('monthChart');
  if (monthCtx) {
    const glass = _isGlass();
    new Chart(monthCtx, {
      type: 'line',
      data: {
        labels: monthLabels,
        datasets: [{
          label: 'Audits',
          data: monthValues,
          borderColor: glass ? 'rgba(77,148,255,0.90)' : '#0d6efd',
          backgroundColor: glass ? 'rgba(13,110,253,0.07)' : 'rgba(13,110,253,0.10)',
          tension: 0.38,
          fill: true,
          pointBackgroundColor: glass ? 'rgba(77,148,255,0.85)' : '#0d6efd',
          pointBorderColor:    glass ? 'rgba(255,255,255,0.60)' : '#0d6efd',
          pointBorderWidth:    glass ? 1.5 : 1,
          pointRadius:         glass ? 4 : 3,
          pointHoverRadius:    glass ? 6 : 5,
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#adb5bd' }, grid: { display: false } },
          y: {
            ticks: { color: '#adb5bd', stepSize: 1 },
            grid:  { color: glass ? 'rgba(255,255,255,0.04)' : 'rgba(255,255,255,0.05)' },
          },
        },
      },
    });
  }
}

/* ── Audit detail charts ────────────────────────────────── */

function initAuditCharts(sevMap, svcLabels, svcValues) {
  const ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'];
  const labels = ORDER.filter(k => sevMap[k] !== undefined);
  const values = labels.map(k => sevMap[k] || 0);
  const colors = labels.map(k => SEV_COLORS[k] || '#495057');

  const sevCtx = document.getElementById('auditSevChart');
  if (sevCtx) {
    const total = values.reduce((a, b) => a + b, 0);
    if (total === 0) {
      // Empty state — replace canvas with a placeholder message
      const wrap = document.getElementById('sevChartWrap');
      if (wrap) {
        wrap.innerHTML = `
          <div class="text-center text-muted py-3">
            <i class="bi bi-shield-check fs-1 d-block mb-2 opacity-25"></i>
            <div class="fw-semibold">No vulnerability records</div>
            <div class="small mt-1 opacity-75">
              No CVE findings were detected in the uploaded files.<br>
              The host <em>Risk</em> score is based on port exposure, not specific CVEs.
            </div>
          </div>`;
      }
    } else {
      const glass = _isGlass();
      new Chart(sevCtx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: glassColors(colors),
            borderWidth:      glass ? 0 : 2,
            borderColor:      glass ? 'transparent' : '#1a1d23',
            hoverOffset:      glass ? 10 : 4,
            hoverBorderWidth: glass ? 2 : 2,
            hoverBorderColor: glass ? 'rgba(255,255,255,0.45)' : '#fff',
          }],
        },
        options: {
          plugins: {
            legend: {
              position: 'right',
              labels: { color: '#adb5bd', font: { size: 11 }, padding: 10, usePointStyle: true, pointStyleWidth: 9 },
            },
          },
          cutout: glass ? '68%' : '65%',
        },
      });
    }
  }

  const svcCtx = document.getElementById('auditSvcChart');
  if (svcCtx) {
    const glass = _isGlass();
    new Chart(svcCtx, {
      type: 'bar',
      data: {
        labels: svcLabels,
        datasets: [{
          label: 'Ports',
          data: svcValues,
          backgroundColor: glass
            ? svcValues.map(() => 'rgba(13,110,253,0.50)')
            : 'rgba(13,110,253,0.72)',
          borderColor:  glass ? 'rgba(13,110,253,0.80)' : undefined,
          borderWidth:  glass ? 1 : 0,
          borderRadius: glass ? 6 : 5,
          hoverBackgroundColor: glass ? 'rgba(13,110,253,0.72)' : 'rgba(13,110,253,0.85)',
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#adb5bd' }, grid: { display: false } },
          y: { ticks: { color: '#adb5bd', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.05)' } },
        },
      },
    });
  }
}

/* ── CVE Modal lookup ───────────────────────────────────── */

function lookupCve(cveId) {
  const modal = new bootstrap.Modal(document.getElementById('cveModal'));
  const body = document.getElementById('cveModalBody');
  document.getElementById('cveModalLabel').innerHTML =
    `<i class="bi bi-shield-exclamation me-2"></i><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}" target="_blank" rel="noopener noreferrer" class="text-decoration-none text-reset">${escHtml(cveId)} <i class="bi bi-box-arrow-up-right small"></i></a>`;
  body.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary" role="status"></div></div>';
  modal.show();

  fetch(`/api/cve/lookup?id=${encodeURIComponent(cveId)}`)
    .then(r => r.json())
    .then(data => {
      if (data.error) {
        body.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
      }
      const sev = data.severity || 'UNKNOWN';
      const sevClass = {
        CRITICAL: 'danger', HIGH: 'warning', MEDIUM: 'warning',
        LOW: 'info', INFO: 'secondary',
      }[sev] || 'secondary';

      let refs = '';
      try {
        const refList = JSON.parse(data.references || '[]');
        refs = refList.slice(0, 5).map(u =>
          `<a href="${escHtml(u)}" target="_blank" rel="noopener noreferrer" class="d-block small text-truncate">${escHtml(u)}</a>`
        ).join('');
      } catch (_) {}

      body.innerHTML = `
        <div class="d-flex gap-2 mb-3 flex-wrap align-items-center">
          <span class="badge bg-${sevClass} fs-6">${sev}</span>
          ${data.cvss_score ? `<span class="badge bg-secondary fs-6">CVSS ${data.cvss_score}</span>` : ''}
          ${data.cvss_vector ? `<code class="small">${escHtml(data.cvss_vector)}</code>` : ''}
          <a href="/cve-remediation/?open=${encodeURIComponent(cveId)}" class="btn btn-sm btn-outline-warning ms-auto" title="View step-by-step remediation">
            <i class="bi bi-wrench-adjustable me-1"></i>Remediation
          </a>
        </div>
        <p class="mb-3">${escHtml(data.description || 'No description available.')}</p>
        ${refs ? `<div class="border-top pt-3"><div class="small fw-semibold mb-1 text-muted">References</div>${refs}</div>` : ''}
        <div id="cve-affected-wrap" class="border-top pt-3 mt-3">
          <div class="small fw-semibold mb-2 text-muted">
            <i class="bi bi-cpu me-1"></i>Affected Software
            <span class="spinner-border spinner-border-sm text-secondary ms-2" id="cve-affected-spinner"></span>
          </div>
          <div id="cve-affected-body"></div>
        </div>
      `;

      // Second fetch: affected software (fires after body is injected)
      fetch(`/api/cve/${encodeURIComponent(cveId)}/affected`)
        .then(r => r.json())
        .then(aff => {
          const spinner = document.getElementById('cve-affected-spinner');
          const affBody = document.getElementById('cve-affected-body');
          const wrap    = document.getElementById('cve-affected-wrap');
          if (spinner) spinner.remove();
          if (!affBody) return;
          if (aff.error || !aff.affected || aff.affected.length === 0) {
            if (wrap) wrap.remove();
            return;
          }
          const TYPE_CLASS = { App: 'primary', OS: 'info', HW: 'secondary' };
          const SHOW_LIMIT = 8;
          const all = aff.affected;

          function renderRows(items) {
            return items.map(a => {
              const vList = a.versions.map(v =>
                v === '*' ? '<span class="text-muted">all versions</span>'
                          : `<code class="small">${escHtml(v)}</code>`
              ).join(' <span class="text-muted mx-1">/</span> ');
              return `<tr>
                <td class="py-1"><span class="badge bg-${TYPE_CLASS[a.type] || 'secondary'}${a.type === 'OS' ? ' text-dark' : ''}">${escHtml(a.type)}</span></td>
                <td class="py-1 small font-monospace">${escHtml(a.vendor)}</td>
                <td class="py-1 small fw-semibold">${escHtml(a.product)}</td>
                <td class="py-1 small">${vList}</td>
              </tr>`;
            }).join('');
          }

          const headerLabel = document.querySelector('#cve-affected-wrap .small.fw-semibold');
          if (headerLabel) {
            headerLabel.innerHTML = `<i class="bi bi-cpu me-1"></i>Affected Software <span class="badge bg-secondary ms-1">${all.length}</span>`;
          }

          const shown = all.slice(0, SHOW_LIMIT);
          const hidden = all.slice(SHOW_LIMIT);
          affBody.innerHTML = `
            <div class="table-responsive">
              <table class="table table-sm table-borderless align-middle mb-0">
                <thead><tr class="text-muted" style="font-size:.75rem">
                  <th class="fw-normal py-1">Type</th>
                  <th class="fw-normal py-1">Vendor</th>
                  <th class="fw-normal py-1">Product</th>
                  <th class="fw-normal py-1">Affected Versions</th>
                </tr></thead>
                <tbody id="cve-aff-shown">${renderRows(shown)}</tbody>
                ${hidden.length ? `<tbody id="cve-aff-hidden" class="d-none">${renderRows(hidden)}</tbody>` : ''}
              </table>
            </div>
            ${hidden.length ? `
              <button class="btn btn-sm btn-link ps-0 text-muted" id="cve-aff-toggle"
                onclick="(function(btn){
                  var h=document.getElementById('cve-aff-hidden');
                  var vis=h.classList.toggle('d-none');
                  btn.textContent = vis ? 'Show ${hidden.length} more…' : 'Show less';
                })(this)">
                Show ${hidden.length} more…
              </button>` : ''}
          `;
        })
        .catch(() => {
          const wrap = document.getElementById('cve-affected-wrap');
          if (wrap) wrap.remove();
        });
    })
    .catch(err => {
      body.innerHTML = `<div class="alert alert-danger">Failed to contact NVD API: ${err}</div>`;
    });
}

function escHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

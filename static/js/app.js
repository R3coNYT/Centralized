/* =========================================================
   Centralized — app.js
   Chart.js initialization + CVE lookup modal
   ========================================================= */

/* ── Chart defaults ─────────────────────────────────────── */

Chart.defaults.color = '#adb5bd';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";

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
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: sevData.labels,
        datasets: [{
          data: sevData.values,
          backgroundColor: sevData.colors,
          borderWidth: 2,
          borderColor: '#1a1d23',
        }],
      },
      options: {
        plugins: {
          legend: { position: 'right', labels: { color: '#adb5bd', font: { size: 12 }, padding: 12 } },
        },
        cutout: '68%',
      },
    });
  }

  // Services bar
  const svcCtx = document.getElementById('svcChart');
  if (svcCtx) {
    new Chart(svcCtx, {
      type: 'bar',
      data: {
        labels: svcLabels,
        datasets: [{
          label: 'Ports',
          data: svcValues,
          backgroundColor: 'rgba(13,110,253,0.7)',
          borderRadius: 5,
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

  // Monthly line chart
  const monthCtx = document.getElementById('monthChart');
  if (monthCtx) {
    new Chart(monthCtx, {
      type: 'line',
      data: {
        labels: monthLabels,
        datasets: [{
          label: 'Audits',
          data: monthValues,
          borderColor: '#0d6efd',
          backgroundColor: 'rgba(13,110,253,0.1)',
          tension: 0.35,
          fill: true,
          pointBackgroundColor: '#0d6efd',
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
      new Chart(sevCtx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{ data: values, backgroundColor: colors, borderWidth: 2, borderColor: '#1a1d23' }],
        },
        options: {
          plugins: { legend: { position: 'right', labels: { color: '#adb5bd', font: { size: 11 }, padding: 10 } } },
          cutout: '65%',
        },
      });
    }
  }

  const svcCtx = document.getElementById('auditSvcChart');
  if (svcCtx) {
    new Chart(svcCtx, {
      type: 'bar',
      data: {
        labels: svcLabels,
        datasets: [{
          label: 'Ports',
          data: svcValues,
          backgroundColor: 'rgba(13,110,253,0.7)',
          borderRadius: 5,
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
    `<i class="bi bi-shield-exclamation me-2"></i>${cveId}`;
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
        <div class="d-flex gap-3 mb-3 flex-wrap">
          <span class="badge bg-${sevClass} fs-6">${sev}</span>
          ${data.cvss_score ? `<span class="badge bg-secondary fs-6">CVSS ${data.cvss_score}</span>` : ''}
          ${data.cvss_vector ? `<code class="small">${escHtml(data.cvss_vector)}</code>` : ''}
        </div>
        <p class="mb-3">${escHtml(data.description || 'No description available.')}</p>
        ${refs ? `<div class="border-top pt-3"><div class="small fw-semibold mb-1 text-muted">References</div>${refs}</div>` : ''}
      `;
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

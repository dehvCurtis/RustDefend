// RustDefend Dashboard — Vanilla JS

let findings = [];
let sortColumn = 'severity';
let sortDirection = 'desc';

const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };

document.getElementById('file-input').addEventListener('change', handleFileLoad);
document.getElementById('filter-severity').addEventListener('change', renderTable);
document.getElementById('filter-chain').addEventListener('change', renderTable);
document.getElementById('filter-search').addEventListener('input', renderTable);

document.querySelectorAll('thead th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (sortColumn === col) {
      sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      sortColumn = col;
      sortDirection = col === 'severity' ? 'desc' : 'asc';
    }
    renderTable();
  });
});

function handleFileLoad(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    try {
      const data = JSON.parse(e.target.result);
      findings = Array.isArray(data) ? data : [];
      renderTable();
    } catch (err) {
      alert('Failed to parse JSON: ' + err.message);
    }
  };
  reader.readAsText(file);
}

function getFilteredFindings() {
  const sevFilter = document.getElementById('filter-severity').value;
  const chainFilter = document.getElementById('filter-chain').value;
  const search = document.getElementById('filter-search').value.toLowerCase();

  return findings.filter(f => {
    if (sevFilter && f.severity !== sevFilter) return false;
    if (chainFilter && f.chain !== chainFilter) return false;
    if (search) {
      const searchable = [f.detector_id, f.name, f.message, f.file, f.recommendation]
        .join(' ')
        .toLowerCase();
      if (!searchable.includes(search)) return false;
    }
    return true;
  });
}

function sortFindings(data) {
  return data.sort((a, b) => {
    let va = a[sortColumn] || '';
    let vb = b[sortColumn] || '';

    if (sortColumn === 'severity') {
      va = severityOrder[va] || 0;
      vb = severityOrder[vb] || 0;
    } else if (sortColumn === 'line') {
      va = Number(va) || 0;
      vb = Number(vb) || 0;
    } else {
      va = String(va).toLowerCase();
      vb = String(vb).toLowerCase();
    }

    if (va < vb) return sortDirection === 'asc' ? -1 : 1;
    if (va > vb) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });
}

function renderTable() {
  const filtered = sortFindings(getFilteredFindings());
  const tbody = document.getElementById('findings-body');

  // Update stats
  const stats = document.getElementById('stats');
  if (findings.length > 0) {
    const crit = findings.filter(f => f.severity === 'Critical').length;
    const high = findings.filter(f => f.severity === 'High').length;
    const med = findings.filter(f => f.severity === 'Medium').length;
    const low = findings.filter(f => f.severity === 'Low').length;
    stats.textContent = `${findings.length} total | Showing ${filtered.length} | C:${crit} H:${high} M:${med} L:${low}`;
  } else {
    stats.textContent = '';
  }

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">' +
      (findings.length === 0 ? 'Load a RustDefend JSON report to view findings' : 'No findings match filters') +
      '</td></tr>';
    return;
  }

  let html = '';
  filtered.forEach((f, i) => {
    const sevClass = 'severity-' + (f.severity || '').toLowerCase();
    const filePath = typeof f.file === 'string' ? f.file : (f.file || '');
    const shortFile = filePath.split('/').slice(-2).join('/');

    html += `<tr>
      <td>${esc(f.detector_id)}</td>
      <td>${esc(f.name)}</td>
      <td class="${sevClass}">${esc(f.severity)}</td>
      <td>${esc(f.confidence)}</td>
      <td>${esc(f.chain)}</td>
      <td title="${esc(filePath)}">${esc(shortFile)}</td>
      <td>${f.line || ''}</td>
      <td><button class="expand-btn" onclick="toggleDetail(${i})">+</button></td>
    </tr>`;

    html += `<tr class="detail-row" id="detail-${i}">
      <td colspan="8" class="detail-cell">
        <div class="label">Message</div>
        <div>${esc(f.message)}</div>
        <div class="label">Snippet</div>
        <pre>${esc(f.snippet || '')}</pre>
        <div class="label">Recommendation</div>
        <div>${esc(f.recommendation || '')}</div>
        <div class="label">File</div>
        <div>${esc(filePath)}:${f.line || ''}</div>
      </td>
    </tr>`;
  });

  tbody.innerHTML = html;
}

function toggleDetail(index) {
  const row = document.getElementById('detail-' + index);
  if (row) {
    row.classList.toggle('expanded');
    const btn = row.previousElementSibling.querySelector('.expand-btn');
    if (btn) {
      btn.textContent = row.classList.contains('expanded') ? '-' : '+';
    }
  }
}

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

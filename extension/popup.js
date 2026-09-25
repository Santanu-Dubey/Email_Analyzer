/**
 * PhishGuard — Extension Popup Controller
 * Manages standalone URL threat scanning, clipboard pasting, demo shortcuts,
 * and backend health monitoring.
 */

const API_BASE_URL = 'http://localhost:8000';

document.addEventListener('DOMContentLoaded', () => {
  const urlInput = document.getElementById('url-input');
  const btnScan = document.getElementById('btn-scan-url');
  const btnPaste = document.getElementById('btn-paste');
  const loadingDiv = document.getElementById('loading-spinner');
  const errorDiv = document.getElementById('popup-error');
  const errorMsg = document.getElementById('error-message');
  const resultCard = document.getElementById('result-card');
  const backendStatus = document.getElementById('backend-status');
  const statusText = document.getElementById('status-text');

  // Check backend server status immediately on popup open
  checkBackendHealth();

  // Handle URL scanning on button click
  btnScan.addEventListener('click', () => {
    const targetUrl = urlInput.value.trim();
    if (targetUrl) {
      performUrlScan(targetUrl);
    } else {
      urlInput.focus();
    }
  });

  // Allow Enter key to trigger scan
  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const targetUrl = urlInput.value.trim();
      if (targetUrl) {
        performUrlScan(targetUrl);
      }
    }
  });

  // Handle Clipboard Paste
  btnPaste.addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        urlInput.value = text.trim();
        urlInput.focus();
      }
    } catch (err) {
      console.warn('Clipboard read failed:', err);
    }
  });

  // Bind Quick Sample Demo Chips
  document.querySelectorAll('.sample-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const sampleUrl = chip.getAttribute('data-url');
      if (sampleUrl) {
        urlInput.value = sampleUrl;
        performUrlScan(sampleUrl);
      }
    });
  });

  /**
   * Check if the FastAPI backend is running and reachable.
   */
  async function checkBackendHealth() {
    try {
      const res = await fetch(`${API_BASE_URL}/health`, { method: 'GET' });
      if (res.ok) {
        backendStatus.className = 'status-pill status-online';
        statusText.innerText = 'Connected';
      } else {
        throw new Error('Server returned non-200');
      }
    } catch (e) {
      backendStatus.className = 'status-pill status-offline';
      statusText.innerText = 'Offline';
    }
  }

  /**
   * Execute URL analysis via backend /scan-url endpoint.
   */
  async function performUrlScan(url) {
    // Reset views
    errorDiv.style.display = 'none';
    resultCard.style.display = 'none';
    loadingDiv.style.display = 'flex';
    btnScan.disabled = true;

    try {
      const response = await fetch(`${API_BASE_URL}/scan-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
      });

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errText}`);
      }

      const data = await response.json();
      renderUrlResult(data);
      backendStatus.className = 'status-pill status-online';
      statusText.innerText = 'Connected';

    } catch (err) {
      console.error('URL Scan failed:', err);
      backendStatus.className = 'status-pill status-offline';
      statusText.innerText = 'Offline';

      errorMsg.innerHTML = `
        <strong>Could not connect to backend:</strong><br>
        Make sure <code>python api_server.py</code> is running on <code>${API_BASE_URL}</code>.<br>
        <small style="opacity: 0.7;">Error: ${escapeHtml(err.message)}</small>
      `;
      errorDiv.style.display = 'block';
    } finally {
      loadingDiv.style.display = 'none';
      btnScan.disabled = false;
    }
  }

  /**
   * Render the URL scan result card inside popup.
   */
  function renderUrlResult(data) {
    const verdictEl = document.getElementById('result-status');
    const domainEl = document.getElementById('result-domain');
    const scorePillEl = document.getElementById('result-score-pill');
    const summaryEl = document.getElementById('result-summary');
    const recEl = document.getElementById('result-recommendation');
    const reasonsContainer = document.getElementById('result-reasons');

    // Update verdict & theme
    verdictEl.innerText = data.status.toUpperCase();
    verdictEl.className = `result-verdict verdict-${data.status.toLowerCase()}`;
    domainEl.innerText = data.domain || data.url;

    scorePillEl.innerText = `Score: ${data.score}/100 (${data.risk})`;
    scorePillEl.style.borderColor = data.color || '#3B82F6';

    summaryEl.innerText = data.explanation?.summary || 'Analysis complete.';
    recEl.innerHTML = `<strong>Action:</strong> ${escapeHtml(data.explanation?.recommendation || 'Verify destination carefully.')}`;

    // Render flagged reasons
    reasonsContainer.innerHTML = '';
    if (data.reasons && data.reasons.length > 0) {
      data.reasons.forEach((reason) => {
        const item = document.createElement('div');
        item.className = 'reason-item';
        item.innerHTML = `<span class="reason-bullet">›</span> <span>${escapeHtml(reason)}</span>`;
        reasonsContainer.appendChild(item);
      });
    } else {
      reasonsContainer.innerHTML = `<div class="reason-clean">✓ Passed all security and lookalike checks.</div>`;
    }

    resultCard.style.display = 'block';
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.innerText = str;
    return div.innerHTML;
  }
});

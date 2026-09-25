/**
 * ===========================================================================
 * PhishGuard — Gmail Content Script (Manifest V3)
 * ===========================================================================
 * 
 * HOW TO INSPECT & UPDATE GMAIL SELECTORS IF GMAIL UPDATES ITS UI:
 * 1. Open Gmail (mail.google.com) and click to open any email.
 * 2. Right-click on the Subject, Sender name, or Body text, and choose "Inspect".
 * 3. In the Elements tab of DevTools:
 *    - Subject is typically inside an <h2> element (look for class "hP" or role).
 *    - Sender is typically a <span> with class "gD" and an attribute like email="name@domain.com".
 *    - Body text is inside a <div> with class "a3s" or "aiL".
 *    - Toolbar is the row of icons above the email with class "G-tF" or role="toolbar".
 * 4. If Google modifies any class names, simply add the new selector to the 
 *    corresponding fallback array below.
 * ===========================================================================
 */

(function () {
  'use strict';

  console.log('[PhishGuard] Content script initialized on Gmail.');

  // Configuration
  const API_BASE_URL = 'http://localhost:8000';
  const POLL_INTERVAL_MS = 1500;
  const BUTTON_ID = 'phishguard-scan-btn';
  const BADGE_ID = 'phishguard-result-badge';

  // Tracking state to detect email changes in Gmail's Single Page App (SPA)
  let lastScannedSubject = null;
  let currentScanning = false;

  // -------------------------------------------------------------------------
  // DOM SELECTORS (Configured with multiple fallback candidates)
  // -------------------------------------------------------------------------

  const SELECTORS = {
    // Top action toolbar where Gmail puts Archive, Delete, Spam, etc.
    toolbars: [
      '.G-tF',                    // Standard Gmail top action toolbar
      'div[role="toolbar"]',      // ARIA toolbar container
      '.aqL',                     // Secondary action bar
      '.ha',                      // Subject header row container
      'div[role="main"] .G-atb'   // Main container action bar
    ],

    // Email Subject heading
    subjects: [
      'h2.hP',                    // Primary Gmail open-thread subject
      '[data-thread-perm-id] h2', // Thread container subject
      'div[role="main"] h2',      // Any <h2> inside main email view
      'h2[data-legacy-thread-id]',// Legacy thread ID heading
      '.ha h2'                    // Header container heading
    ],

    // Sender Name and Email Address
    senders: [
      'span.gD[email]',           // Primary sender span with email attribute
      'span.gD',                  // Sender display name wrapper
      'div[role="main"] [email]', // Any element with email attribute in main view
      'span[email]',              // Generic span with email attribute
      'span.go',                  // Sender email address sub-element
      '.gE.iv.gt span[email]'     // Expanded header sender span
    ],

    // Email Body Content
    bodies: [
      'div.a3s.aiL',              // Primary message body container
      'div.a3s',                  // Generic message body wrapper
      'div.ii.gt div.a3s',        // Expanded message item body
      'div[dir="ltr"]',           // Text direction container inside message
      'div[role="listitem"] div.a3s' // List item message container
    ]
  };

  // -------------------------------------------------------------------------
  // HELPER: Query with Multi-Selector Fallback
  // -------------------------------------------------------------------------

  /**
   * Tries an array of CSS selectors in order and returns the first matching element.
   * @param {string[]} selectorList - Array of CSS selector strings
   * @param {Element|Document} root - Context root (defaults to document)
   * @returns {Element|null}
   */
  function queryFallback(selectorList, root = document) {
    for (const sel of selectorList) {
      try {
        const el = root.querySelector(sel);
        if (el) return el;
      } catch (e) {
        // Continue to next fallback if selector fails
      }
    }
    return null;
  }

  /**
   * Extracts clean text content from the current email view.
   */
  function extractEmailData() {
    // 1. Extract Subject
    let subject = '';
    const subjectEl = queryFallback(SELECTORS.subjects);
    if (subjectEl && subjectEl.innerText) {
      subject = subjectEl.innerText.trim();
    } else {
      // Fallback: Parse document title (e.g. "Important Update - User - Gmail")
      const title = document.title || '';
      subject = title.replace(/\s*-\s*Gmail$/i, '').trim();
    }

    // 2. Extract Sender
    let sender = '';
    const senderEl = queryFallback(SELECTORS.senders);
    if (senderEl) {
      const emailAttr = senderEl.getAttribute('email');
      const nameText = senderEl.innerText ? senderEl.innerText.trim() : '';
      if (emailAttr && nameText && nameText !== emailAttr) {
        sender = `${nameText} <${emailAttr}>`;
      } else if (emailAttr) {
        sender = emailAttr;
      } else {
        sender = nameText;
      }
    }

    // 3. Extract Body & Links
    let bodyText = '';
    const links = [];
    const bodyEl = queryFallback(SELECTORS.bodies);

    if (bodyEl) {
      bodyText = bodyEl.innerText ? bodyEl.innerText.trim() : '';

      // Extract all anchor links inside the email body
      const anchorTags = bodyEl.querySelectorAll('a[href]');
      anchorTags.forEach((a) => {
        const href = a.getAttribute('href') || a.href || '';
        const text = a.innerText ? a.innerText.trim() : '';
        if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
          // Avoid internal Gmail / Google UI navigation links
          if (!href.includes('mail.google.com/mail/u/')) {
            links.push({ text: text || href, href: href });
          }
        }
      });
    }

    return {
      sender: sender || 'Unknown Sender',
      subject: subject || '(No Subject)',
      body: bodyText,
      links: links
    };
  }

  // -------------------------------------------------------------------------
  // SCAN BUTTON INJECTION & LIFECYCLE
  // -------------------------------------------------------------------------

  /**
   * Injects or updates the PhishGuard Scan Button in Gmail's active toolbar.
   */
  function injectScanButton() {
    // Verify an email is currently open by checking for a subject or body
    const hasOpenEmail = queryFallback(SELECTORS.subjects) || queryFallback(SELECTORS.bodies);
    if (!hasOpenEmail) {
      // User is in inbox list view or settings, remove button if present
      const existingBtn = document.getElementById(BUTTON_ID);
      if (existingBtn) existingBtn.remove();
      return;
    }

    // Check if the user navigated to a DIFFERENT email
    const subjectEl = queryFallback(SELECTORS.subjects);
    const currentSubject = subjectEl ? subjectEl.innerText.trim() : '';
    if (currentSubject && lastScannedSubject && currentSubject !== lastScannedSubject) {
      // User switched emails! Reset stale result badge and update tracking
      removeResultBadge();
      lastScannedSubject = null;
    }

    // Check if button already exists in the DOM to avoid duplication
    if (document.getElementById(BUTTON_ID)) {
      return;
    }

    // Locate toolbar to attach button
    const toolbar = queryFallback(SELECTORS.toolbars);
    if (!toolbar) {
      return;
    }

    // Create the PhishGuard Scan Button
    const btn = document.createElement('button');
    btn.id = BUTTON_ID;
    btn.className = 'phishguard-btn';
    btn.setAttribute('type', 'button');
    btn.setAttribute('title', 'Scan this email for phishing, spoofing, and malicious links');
    btn.innerHTML = `
      <span class="phishguard-btn-icon">🛡️</span>
      <span class="phishguard-btn-label">Scan for Phishing</span>
    `;

    btn.addEventListener('click', handleScanClick);

    // Insert button into toolbar (prepend or append cleanly)
    toolbar.appendChild(btn);
  }

  // -------------------------------------------------------------------------
  // SCANNING ACTION & BACKEND API CALL
  // -------------------------------------------------------------------------

  /**
   * Handles user click on "Scan for Phishing" button.
   */
  async function handleScanClick(e) {
    if (e) e.preventDefault();
    if (currentScanning) return;

    const btn = document.getElementById(BUTTON_ID);
    const originalContent = btn ? btn.innerHTML : '';

    try {
      currentScanning = true;
      if (btn) {
        btn.classList.add('phishguard-btn-loading');
        btn.innerHTML = `<span class="phishguard-spinner"></span> Scanning...`;
      }

      // Extract live DOM email data
      const emailData = extractEmailData();
      lastScannedSubject = emailData.subject;

      console.log('[PhishGuard] Sending email payload to backend:', {
        sender: emailData.sender,
        subject: emailData.subject,
        body_length: emailData.body.length,
        links_count: emailData.links.length
      });

      // Call PhishGuard FastAPI backend
      const response = await fetch(`${API_BASE_URL}/scan-email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(emailData)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Server returned HTTP ${response.status}: ${errorText}`);
      }

      const scanResult = await response.json();
      console.log('[PhishGuard] Received scan result:', scanResult);

      // Render rich forensic result badge
      renderResultBadge(scanResult, emailData);

    } catch (err) {
      console.error('[PhishGuard] Scan failed:', err);
      renderErrorBadge(err);
    } finally {
      currentScanning = false;
      if (btn) {
        btn.classList.remove('phishguard-btn-loading');
        btn.innerHTML = originalContent;
      }
    }
  }

  // -------------------------------------------------------------------------
  // RESULT BADGE UI RENDERING
  // -------------------------------------------------------------------------

  /**
   * Renders the interactive, color-coded forensic result card.
   */
  function renderResultBadge(result, emailData) {
    removeResultBadge();

    const badge = document.createElement('div');
    badge.id = BADGE_ID;
    badge.className = `phishguard-badge phishguard-badge-${result.status.toLowerCase()}`;

    // Color theme & status icon
    let statusIcon = '🛡️';
    let statusThemeClass = 'status-safe';
    if (result.status === 'Phishing') {
      statusIcon = '🚨';
      statusThemeClass = 'status-phish';
    } else if (result.status === 'Suspicious') {
      statusIcon = '⚠️';
      statusThemeClass = 'status-suspicious';
    }

    // Build evidence flag checklist items
    let reasonsHtml = '';
    if (result.flagged && result.flagged.length > 0) {
      reasonsHtml = result.flagged
        .map(
          (f) => `
          <div class="phishguard-evidence-item">
            <span class="phishguard-evidence-pts">+${f.weight || 0} pts</span>
            <div class="phishguard-evidence-desc">
              <strong>${escapeHtml(f.check || 'Security Check')}:</strong> ${escapeHtml(f.explanation || '')}
            </div>
          </div>
        `
        )
        .join('');
    } else {
      reasonsHtml = `
        <div class="phishguard-evidence-item phishguard-evidence-pass">
          <span class="phishguard-evidence-icon">✓</span>
          <div class="phishguard-evidence-desc">
            No malicious indicators, domain typosquatting, or deceptive links detected.
          </div>
        </div>
      `;
    }

    // Build category scores breakdown pills
    const cats = result.category_scores || {};
    const categoryPillsHtml = Object.entries(cats)
      .map(
        ([name, score]) => `
        <span class="phishguard-pill ${score > 0 ? 'pill-alert' : 'pill-clean'}">
          ${escapeHtml(name)}: ${score > 0 ? `+${score}` : '0'}
        </span>
      `
      )
      .join('');

    badge.innerHTML = `
      <div class="phishguard-card-header">
        <div class="phishguard-title-group">
          <span class="phishguard-badge-icon">${statusIcon}</span>
          <div>
            <div class="phishguard-badge-title">PhishGuard Forensics</div>
            <div class="phishguard-badge-subtitle">${escapeHtml(emailData.sender || 'Sender')}</div>
          </div>
        </div>
        <button class="phishguard-close-btn" id="phishguard-close-btn" title="Close Panel">✕</button>
      </div>

      <div class="phishguard-score-banner ${statusThemeClass}">
        <div class="phishguard-verdict-title">${escapeHtml(result.status.toUpperCase())}</div>
        <div class="phishguard-score-pill">Threat Score: ${result.score}/100 (${escapeHtml(result.risk)})</div>
      </div>

      <div class="phishguard-section">
        <div class="phishguard-section-title">💡 Security Analysis</div>
        <div class="phishguard-explanation-text">
          ${escapeHtml(result.explanation?.summary || 'Analysis complete.')}
        </div>
        ${
          result.explanation?.recommendation
            ? `<div class="phishguard-recommendation-box">
                <strong>Action:</strong> ${escapeHtml(result.explanation.recommendation)}
               </div>`
            : ''
        }
      </div>

      <div class="phishguard-section">
        <div class="phishguard-section-title">🚩 Triggered Evidence (${result.flagged ? result.flagged.length : 0})</div>
        <div class="phishguard-evidence-list">
          ${reasonsHtml}
        </div>
      </div>

      <div class="phishguard-section">
        <div class="phishguard-section-title">📊 Category Breakdown</div>
        <div class="phishguard-pills-row">
          ${categoryPillsHtml}
        </div>
      </div>

      <div class="phishguard-footer">
        <span>🔗 ${emailData.links.length} Link(s) Inspected</span>
        <span>⚡ ${escapeHtml(result.explanation?.source || 'PhishGuard AI')}</span>
      </div>
    `;

    document.body.appendChild(badge);

    // Bind close event
    const closeBtn = badge.querySelector('#phishguard-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', removeResultBadge);
    }
  }

  /**
   * Renders a friendly error badge when the Python backend is not running.
   */
  function renderErrorBadge(err) {
    removeResultBadge();

    const badge = document.createElement('div');
    badge.id = BADGE_ID;
    badge.className = 'phishguard-badge phishguard-badge-error';

    badge.innerHTML = `
      <div class="phishguard-card-header">
        <div class="phishguard-title-group">
          <span class="phishguard-badge-icon">⚠️</span>
          <div>
            <div class="phishguard-badge-title">PhishGuard Connection Error</div>
            <div class="phishguard-badge-subtitle">Backend Server Offline</div>
          </div>
        </div>
        <button class="phishguard-close-btn" id="phishguard-close-btn" title="Close">✕</button>
      </div>

      <div class="phishguard-error-body">
        <p>Could not connect to the PhishGuard analysis backend at <code>${API_BASE_URL}</code>.</p>
        <div class="phishguard-fix-box">
          <strong>To resolve this:</strong>
          <ol>
            <li>Open terminal in <code>Email_Analyzer</code> folder</li>
            <li>Run: <code>python api_server.py</code></li>
            <li>Ensure server is running on <code>http://127.0.0.1:8000</code></li>
            <li>Click "Scan for Phishing" again</li>
          </ol>
        </div>
        <small class="phishguard-error-raw">Detail: ${escapeHtml(err.message || String(err))}</small>
      </div>
    `;

    document.body.appendChild(badge);

    const closeBtn = badge.querySelector('#phishguard-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', removeResultBadge);
    }
  }

  function removeResultBadge() {
    const existing = document.getElementById(BADGE_ID);
    if (existing) {
      existing.remove();
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.innerText = str;
    return div.innerHTML;
  }

  // -------------------------------------------------------------------------
  // POLLING ENGINE (Single Page App Navigation Watcher)
  // -------------------------------------------------------------------------

  // Run periodic loop to monitor Gmail DOM updates and page navigations
  setInterval(() => {
    try {
      injectScanButton();
    } catch (e) {
      console.warn('[PhishGuard] Poller error:', e);
    }
  }, POLL_INTERVAL_MS);

  // Initial check
  injectScanButton();

})();

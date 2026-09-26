/**
 * ===========================================================================
 * PhishGuard — Gmail Content Script (Manifest V3)
 * ===========================================================================
 * 
 * DUAL SCAN ARCHITECTURE:
 * 1. Primary: Fetches raw RFC 5322 email bytes via Gmail REST API
 *    (/gmail/v1/users/me/messages/<id>?format=raw) using OAuth2 tokens.
 *    Provides real SPF, DKIM, and DMARC cryptographic header verification.
 * 2. Fallback: Automatically falls back to DOM scraping (/scan-email) if OAuth,
 *    network, permissions, or Gmail API requests fail for any reason.
 * 
 * HOW TO INSPECT & UPDATE GMAIL SELECTORS IF GMAIL UPDATES ITS UI:
 * 1. Open Gmail (mail.google.com) and click to open any email.
 * 2. Right-click on Subject, Sender, or Body and click "Inspect".
 * 3. Update the SELECTORS configuration below as needed.
 * ===========================================================================
 */

(function () {
  'use strict';

  console.log('[PhishGuard] Content script initialized on Gmail.');

  // Configuration
  const API_BASE_URL = 'http://127.0.0.1:8000';
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
  // GMAIL MESSAGE ID EXTRACTION
  // -------------------------------------------------------------------------

  /**
   * Extracts the currently open Gmail message or thread ID from the URL hash.
   * 
   * NOTE FOR USERS / DEVELOPERS:
   * Gmail URL structures can vary based on account indices (/u/0/, /u/1/), custom views,
   * search queries, and categories.
   * Typical URL hash formats:
   *   - Standard Inbox:  https://mail.google.com/mail/u/0/#inbox/<messageId>
   *   - All Mail:        https://mail.google.com/mail/u/0/#all/<messageId>
   *   - Sent Items:      https://mail.google.com/mail/u/0/#sent/<messageId>
   *   - Search Results:  https://mail.google.com/mail/u/0/#search/<query>/<messageId>
   *   - Custom Labels:   https://mail.google.com/mail/u/0/#label/<labelName>/<messageId>
   * If your live Gmail URL pattern differs, verify `window.location.hash` in DevTools.
   * 
   * @returns {string|null} Hex/alphanumeric Gmail message ID or null
   */
  function extractGmailMessageId() {
    const hash = window.location.hash || '';
    if (!hash) return null;

    // Pattern 1: Match after known Gmail standard views (#inbox/<id>, #all/<id>, #sent/<id>, #spam/<id>, etc.)
    const folderMatch = hash.match(/#(?:inbox|sent|starred|snoozed|drafts|imp|spam|trash|all|category\/[^\/]+)\/([a-zA-Z0-9_-]+)/i);
    if (folderMatch && folderMatch[1]) {
      return folderMatch[1];
    }

    // Pattern 2: Match after search/label nested paths (#search/query/<id> or #label/name/<id>)
    const searchOrLabelMatch = hash.match(/#(?:search|label)\/(?:.+)\/([a-zA-Z0-9_-]+)/i);
    if (searchOrLabelMatch && searchOrLabelMatch[1]) {
      return searchOrLabelMatch[1];
    }

    // Pattern 3: General fallback — match any hash path ending in a 12+ char hex/alphanumeric ID
    const generalIdMatch = hash.match(/#(?:.*\/)?([a-zA-Z0-9_-]{12,})/i);
    if (generalIdMatch && generalIdMatch[1]) {
      const candidate = generalIdMatch[1];
      const ignored = ['inbox', 'sent', 'starred', 'drafts', 'imp', 'trash', 'spam', 'all', 'settings'];
      if (!ignored.includes(candidate.toLowerCase())) {
        return candidate;
      }
    }

    // Pattern 4: Last segment of the hash if separated by slash
    const segments = hash.replace(/^#\/?/, '').split('/');
    if (segments.length > 1) {
      const last = segments[segments.length - 1];
      if (last && last.length >= 8) {
        return last;
      }
    }

    // Pattern 5: DOM Fallback for legacy thread/message ID attribute
    try {
      const messageEl = document.querySelector('[data-message-id], [data-legacy-message-id], [data-thread-perm-id]');
      if (messageEl) {
        const domId = messageEl.getAttribute('data-message-id') ||
                      messageEl.getAttribute('data-legacy-message-id') ||
                      messageEl.getAttribute('data-thread-perm-id');
        if (domId) {
          return domId.replace(/^#/, '');
        }
      }
    } catch (e) {
      // Ignore DOM query errors
    }

    return null;
  }

  // -------------------------------------------------------------------------
  // GMAIL API & OAUTH TOKEN ACQUISITION
  // -------------------------------------------------------------------------

  /**
   * Retrieves an OAuth 2.0 access token with gmail.readonly scope.
   * Works in Manifest V3 via background service worker delegation or direct API if available.
   * @param {boolean} interactive - Whether to prompt the user if unauthenticated
   * @returns {Promise<string>} OAuth access token
   */
  async function getAuthToken(interactive = true) {
    // If chrome.identity is directly accessible in current scope:
    if (typeof chrome !== 'undefined' && chrome.identity && chrome.identity.getAuthToken) {
      return new Promise((resolve, reject) => {
        chrome.identity.getAuthToken({ interactive }, (token) => {
          if (chrome.runtime.lastError || !token) {
            reject(new Error(chrome.runtime.lastError ? chrome.runtime.lastError.message : 'No OAuth token returned'));
          } else {
            resolve(token);
          }
        });
      });
    }

    // In MV3 content scripts, delegate token request to background service worker
    return new Promise((resolve, reject) => {
      if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
        return reject(new Error('chrome.runtime messaging is unavailable'));
      }
      chrome.runtime.sendMessage({ action: 'GET_AUTH_TOKEN', interactive }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else if (response && response.success && response.token) {
          resolve(response.token);
        } else {
          reject(new Error(response?.error || 'Failed to acquire OAuth token from background service worker'));
        }
      });
    });
  }

  /**
   * Fetches raw RFC 5322 email string (base64url encoded) from Gmail REST API.
   * @param {string} messageId - The Gmail message ID
   * @param {string} token - The OAuth access token
   * @returns {Promise<string>} Base64url raw string
   */
  async function fetchGmailRawEmail(messageId, token) {
    const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(messageId)}?format=raw`;

    // Try direct fetch from content script first
    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        if (data && data.raw) {
          return data.raw;
        }
        throw new Error('Gmail API response did not contain "raw" field');
      }
    } catch (directErr) {
      console.warn('[PhishGuard] Direct Gmail API fetch failed, trying background service worker proxy...', directErr);
    }

    // Delegate to background service worker proxy
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action: 'FETCH_GMAIL_RAW', messageId, token }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else if (response && response.success && response.data && response.data.raw) {
          resolve(response.data.raw);
        } else {
          reject(new Error(response?.error || `Failed to fetch raw message for ID ${messageId}`));
        }
      });
    });
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
  // SCANNING ACTION WITH AUTOMATIC FALLBACK
  // -------------------------------------------------------------------------

  /**
   * Handles user click on "Scan for Phishing" button.
   * 1. Attempts the Gmail API path (/scan-raw with full RFC 5322 headers).
   * 2. If ANY error occurs (auth, network, missing message ID, API error),
   *    silently falls back to the DOM scraping path (/scan-email).
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

      // Always extract DOM data for fallback and context display
      const emailData = extractEmailData();
      lastScannedSubject = emailData.subject;

      let scanResult = null;
      let scanMethod = 'DOM'; // 'API' | 'DOM'

      // =====================================================================
      // STEP 1: ATTEMPT GMAIL API (FULL RFC 5322 RAW HEADERS) PATH
      // =====================================================================
      try {
        const messageId = extractGmailMessageId();
        if (!messageId) {
          throw new Error('Could not identify Gmail message ID from URL hash or DOM');
        }

        console.log('[PhishGuard] Trying Gmail API path for message ID:', messageId);
        const authToken = await getAuthToken(true);
        console.log('[PhishGuard] Acquired OAuth token, fetching raw message from Gmail API...');

        const rawB64 = await fetchGmailRawEmail(messageId, authToken);
        console.log('[PhishGuard] Successfully fetched raw email bytes, sending to /scan-raw...');

        const apiResponse = await fetch(`${API_BASE_URL}/scan-raw`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ raw: rawB64 })
        });

        if (!apiResponse.ok) {
          const errText = await apiResponse.text();
          throw new Error(`Backend /scan-raw returned HTTP ${apiResponse.status}: ${errText}`);
        }

        scanResult = await apiResponse.json();
        scanMethod = 'API';
        console.log('[PhishGuard] Gmail API raw scan succeeded:', scanResult);

      } catch (apiErr) {
        // ===================================================================
        // STEP 2: AUTOMATIC FALLBACK TO DOM SCRAPING PATH
        // ===================================================================
        console.warn('[PhishGuard] Gmail API path failed, falling back to DOM scraping:', apiErr.message || apiErr);

        console.log('[PhishGuard] Executing DOM fallback: Sending scraped payload to /scan-email...', {
          sender: emailData.sender,
          subject: emailData.subject,
          body_length: emailData.body.length,
          links_count: emailData.links.length
        });

        const domResponse = await fetch(`${API_BASE_URL}/scan-email`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(emailData)
        });

        if (!domResponse.ok) {
          const errorText = await domResponse.text();
          throw new Error(`Backend /scan-email returned HTTP ${domResponse.status}: ${errorText}`);
        }

        scanResult = await domResponse.json();
        scanMethod = 'DOM';
        console.log('[PhishGuard] Fallback DOM scan succeeded:', scanResult);
      }

      // Render rich forensic result badge with scan method indicator
      renderResultBadge(scanResult, emailData, scanMethod);

    } catch (err) {
      console.error('[PhishGuard] All scan methods failed:', err);
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
   * @param {object} result - Backend analysis result
   * @param {object} emailData - Extracted DOM metadata
   * @param {string} scanMethod - 'API' or 'DOM'
   */
  function renderResultBadge(result, emailData, scanMethod = 'DOM') {
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

    // Method indicator UI badge and footer text
    const isApiScan = scanMethod === 'API';
    const methodBadgeHtml = isApiScan
      ? `<div class="phishguard-method-tag tag-api" title="Scanned via Gmail API with full cryptographic RFC 5322 header forensics (SPF, DKIM, DMARC)">
          <span class="phishguard-method-dot">●</span> via Gmail API (full header analysis)
        </div>`
      : `<div class="phishguard-method-tag tag-dom" title="Scanned via page DOM scraper. SPF/DKIM/DMARC headers are unavailable in the browser DOM view.">
          <span class="phishguard-method-dot">○</span> via page scan (headers unavailable)
        </div>`;

    const methodFooterHtml = isApiScan
      ? `<span>⚡ via Gmail API (full header analysis)</span>`
      : `<span>⚡ via page scan (headers unavailable)</span>`;

    const senderDisplay = result.meta?.sender || emailData.sender || 'Sender';
    const linksCount = result.meta?.links_scanned ?? emailData.links.length;

    badge.innerHTML = `
      <div class="phishguard-card-header">
        <div class="phishguard-title-group">
          <span class="phishguard-badge-icon">${statusIcon}</span>
          <div>
            <div class="phishguard-badge-title">PhishGuard Forensics</div>
            <div class="phishguard-badge-subtitle">${escapeHtml(senderDisplay)}</div>
          </div>
        </div>
        <button class="phishguard-close-btn" id="phishguard-close-btn" title="Close Panel">✕</button>
      </div>

      <div class="phishguard-method-row">
        ${methodBadgeHtml}
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
        ${methodFooterHtml}
        <span>🔗 ${linksCount} Link(s) Inspected</span>
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

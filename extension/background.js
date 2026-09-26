/**
 * PhishGuard — Background Service Worker (Manifest V3)
 * 
 * In Manifest V3, background scripts run as service workers.
 * This script handles extension installation lifecycle, background messaging,
 * and icon state updates.
 */

// Log when extension is loaded or updated
chrome.runtime.onInstalled.addListener((details) => {
  console.log('[PhishGuard Service Worker] Extension installed successfully. Reason:', details.reason);
});

// Optional message listener for cross-component communication (popup <-> content script)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'PING') {
    sendResponse({ status: 'PONG', timestamp: Date.now() });
    return true;
  }
  
  if (request.action === 'CHECK_BACKEND_STATUS') {
    fetch('http://127.0.0.1:8000/health')
      .then(res => res.json())
      .then(data => sendResponse({ online: true, data }))
      .catch(err => sendResponse({ online: false, error: err.message }));
    return true; // Keep message channel open for async fetch
  }

  // OAuth token retrieval for content scripts (chrome.identity runs in Service Worker in MV3)
  if (request.action === 'GET_AUTH_TOKEN') {
    if (!chrome.identity || !chrome.identity.getAuthToken) {
      sendResponse({ success: false, error: 'chrome.identity API unavailable' });
      return true;
    }
    chrome.identity.getAuthToken({ interactive: request.interactive ?? false }, (token) => {
      if (chrome.runtime.lastError) {
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
      } else if (!token) {
        sendResponse({ success: false, error: 'Failed to acquire OAuth token' });
      } else {
        sendResponse({ success: true, token: token });
      }
    });
    return true; // Async response
  }

  // Proxy Gmail API raw email fetch with OAuth bearer token
  if (request.action === 'FETCH_GMAIL_RAW') {
    const { messageId, token } = request;
    if (!messageId || !token) {
      sendResponse({ success: false, error: 'Missing messageId or token' });
      return true;
    }

    fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(messageId)}?format=raw`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    })
      .then(async (res) => {
        if (!res.ok) {
          const errText = await res.text();
          sendResponse({ success: false, status: res.status, error: `Gmail API HTTP ${res.status}: ${errText}` });
        } else {
          const data = await res.json();
          sendResponse({ success: true, data: data });
        }
      })
      .catch((err) => {
        sendResponse({ success: false, error: err.message || String(err) });
      });
    return true; // Async response
  }
});

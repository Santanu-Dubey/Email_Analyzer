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
    fetch('http://localhost:8000/health')
      .then(res => res.json())
      .then(data => sendResponse({ online: true, data }))
      .catch(err => sendResponse({ online: false, error: err.message }));
    return true; // Keep message channel open for async fetch
  }
});

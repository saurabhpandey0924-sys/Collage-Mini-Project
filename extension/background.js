chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-analyze",
    title: "Analyze for Phishing with PhishGuard",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "phishguard-analyze") {
    // URL to your deployed PhishGuard application
    // Replace with your actual deployed URL, e.g., https://your-domain.com/email-analyzer.html
    const appUrl = "http://localhost:3000/email-analyzer.html"; 
    
    // Construct the URL with query parameters
    const targetUrl = `${appUrl}?text=${encodeURIComponent(info.selectionText)}`;
    
    chrome.tabs.create({ url: targetUrl });
  }
});

chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.create({ url: "http://localhost:3000/email-analyzer.html" });
});

// background/service-worker.js

// 1. Utility function to get OAuth Token (Keep this for Week 2)
async function getAuthToken() {
    return new Promise((resolve, reject) => {
        chrome.identity.getAuthToken({interactive: true}, (token) => {
            if (chrome.runtime.lastError){
                reject(chrome.runtime.lastError);
            } else {
                resolve(token);
            }
        });
    });
}

// 2. The "Smoke Test" - Runs once on install/reload
chrome.runtime.onInstalled.addListener(async() => {
    try {
        const token = await getAuthToken();
        console.log("OAuth token verified on install:", token.slice(0, 20) + "...");
    } catch (err){
        console.error("Initial OAuth check failed:", err);
    }
});

// 3. The Communication Hub - Listens for emails detected by content/gmail_injector.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "EMAIL_DETECTED") {
        console.log("[Background] Received email detection:", message.data);
        
        // This is the bridge to Week 2:
        // message.data.messageId will be used to fetch headers via Gmail API
        
        sendResponse({ status: "received" });
    }
    // Required to keep the message channel open for potential async responses later
    return true; 
});

async function fetchEmailHeaders(messageId) {
    const token = await getAuthToken();

    const response = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=metadata&metadataHeaders=Authentication-Results&metadataHeaders=From&metadataHeaders=Reply-To&metadataHeaders=Received&metadataHeaders=DKIM-Signature&metadataHeaders=Message-ID`,
        {
            headers: {
                Authorization: `Bearer ${token}`
            }
        }
    );

    if (!response.ok) {
        throw new Error(`Gmail API error: ${response.status}`);
    }

    const data = await response.json();

    // By default, the Gmail API returns headers as an array of {name, value} objects. We can transform this into a more convenient Key-Value lookup map to reduce time complexity from O(N) to O(1) for header retrieval.
    const headers = {};
    for (const header of data.payload.headers) {
        headers[header.name.toLowerCase()] = header.value;
    }
    return headers;
}

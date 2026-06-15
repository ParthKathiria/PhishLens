// MutationObserver can fire hundreds of times a second as the page renders.
// The lastAnalyzedMessageId variable variable acts a "memory" to ensure the extension only analyzes a specific email once per open, preventing the backend from being flooded with redundant queries.
let lastAnalyzedMessageId = null;

function getOpenEmailContainer() {
    // Gmail's DOM structure can change, so this selector may need to be updated in the future
    // Currently, Gmail renders the open email in a div with role = "main"
    // The email body is inside a table structure within this div
    // This selector is relatively stable across Gmail UI updates, but may need adjustments if Gmail changes its layout
    return document.querySelector('[role = "main"] .a3s.aiL') || document.querySelector('[role = "main"] .ii.gt');
}

/*
Once an email container is found, we need the metadata.
Subject: It looks for h2.hP, which is the standard header for the subject line.
Sender: It looks for .gD class. Gmail stores the sender's name and email address in "name" and "email" attributes within this tag.
*/
function getEmailSubjectAndSender() {
    const subject = document.querySelector('h2.hP')?.innerText || 
                  document.querySelector('[data-thread-perm-id] h2')?.innerText ||
                  "Unknown Subject";
  
    const senderEl = document.querySelector('.gD');
    const senderName = senderEl?.getAttribute('name') || "Unknown";
    const senderEmail = senderEl?.getAttribute('email') || "Unknown";
    
    return { subject, senderName, senderEmail };
}

// Every Gmail thread has a unique alphanumeric ID. This function uses Regex to pluck that ID from the URL hash.
function getMessageIdFromUrl() {
    // Gmail puts the message/thread ID in the URL hash (e.g., #inbox/PJvcgzQgLrrlBWkseuKJbWVKPtPoNBbrW)
    const hash = window.location.hash;
    const match = hash.match(/#(?:inbox|sent|all|spam)\/([a-zA-Z0-9]+)/);
    return match ? match[1] : null;
}

function onEmailOpened() {
    const messageId = getMessageIdFromUrl();

    // Avoid re-analyzing the same email if DOM updates fire multiple times
    if(messageId && messageId === lastAnalyzedMessageId) return;
    lastAnalyzedMessageId = messageId;

    const emailContainer = getOpenEmailContainer();
    if(!emailContainer) return;

    const {subject, senderName, senderEmail} = getEmailSubjectAndSender();

    console.log("[Phish Lens] Email detected:");
    console.log("   Subject:", subject);
    console.log("   Sender:", senderName, "<" + senderEmail + ">");
    console.log("   Message ID:", messageId);

    // Send the email metadata to the background worker for analysis (TO BE DONE...)
    chrome.runtime.sendMessage ({
        type: "EMAIL_DETECTED",
        data: {subject, senderName, senderEmail, messageId}
    });
}

// Watch the DOM for Gmail loading an email view
const observer = new MutationObserver(() => {
    if(getOpenEmailContainer()) {
        onEmailOpened();
    }
});

observer.observe(document.body, {
    childList: true,
    subtree: true
});

// Also handle direct page loads into an email URL
window.addEventListener('load', () => {
    setTimeout(() => {
        if(getOpenEmailContainer()) onEmailOpened();
    }, 1000);
});
document.getElementById('auth-btn').addEventListener('click', () => {
  document.getElementById('result').innerText = 'Attempting auth...';

  chrome.identity.getAuthToken({ interactive: true }, function(token) {
    if (chrome.runtime.lastError) {
      document.getElementById('result').innerText = 
        'ERROR: ' + JSON.stringify(chrome.runtime.lastError);
    } else {
      document.getElementById('result').innerText = 
        'SUCCESS: ' + token.slice(0, 20) + '...';
    }
  });
});
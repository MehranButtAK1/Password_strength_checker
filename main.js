const passwordInput = document.querySelector('input[type="password"]');
const bar = document.getElementById('bar');
const strengthText = document.getElementById('strengthText');
const breachResult = document.getElementById('breachResult');
const showPasswordCheckbox = document.getElementById('showPassword');

// Debounce function to limit API calls
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Breach checking function
async function checkPasswordBreach(value) {
    if (!value) {
        breachResult.textContent = '';
        return;
    }

    try {
        // Convert password to SHA-1 hash
        const msgBuffer = new TextEncoder().encode(value);
        const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Get first 5 characters of hash for API call
        const prefix = hashHex.slice(0, 5).toUpperCase();
        const suffix = hashHex.slice(5).toUpperCase();

        // Call Have I Been Pwned API
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const data = await response.text();

        // Check if hash suffix exists in response
        const isBreached = data.split('\n').some(line => {
            const [hashSuffix] = line.split(':');
            return hashSuffix === suffix;
        });

        breachResult.textContent = isBreached
            ? 'Warning: This password has been found in a data breach!'
            : 'Good news: This password has not been found in any known data breaches.';
        breachResult.style.color = isBreached ? '#a94442' : '#3c763d';
    } catch (error) {
        breachResult.textContent = 'Error checking password breach.';
        breachResult.style.color = '#a94442';
        console.error('Error:', error);
    }
}

// Debounced breach check (runs every 1000ms max)
const debouncedCheckPasswordBreach = debounce(checkPasswordBreach, 1000);

// Toggle password visibility
showPasswordCheckbox.addEventListener('change', () => {
    passwordInput.type = showPasswordCheckbox.checked ? 'text' : 'password';
});

passwordInput.addEventListener('input', () => {
    const value = passwordInput.value;
    let strength = 0;
    let color = '';
    let width = '0%';
    let text = '';

    if (value.length > 8) strength++;
    if (value.match(/[A-Z]/)) strength++;
    if (value.match(/[0-9]/)) strength++;
    if (value.match(/[^A-Za-z0-9]/)) strength++;

    switch (strength) {
        case 1:
            color = 'red'; width = '25%'; text = 'Weak'; break;
        case 2:
            color = 'orange'; width = '50%'; text = 'Fair'; break;
        case 3:
            color = 'yellow'; width = '75%'; text = 'Good'; break;
        case 4:
            color = 'green'; width = '100%'; text = 'Strong'; break;
        default:
            color = '#475569'; width = '0%'; text = ''; break;
    }

    bar.style.width = width;
    bar.style.backgroundColor = color;
    strengthText.textContent = text;

    // Trigger breach check
    debouncedCheckPasswordBreach(value);
});

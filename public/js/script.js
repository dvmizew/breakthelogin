console.log('AuthX Security Console Loaded...');

document.addEventListener('DOMContentLoaded', () => {
    const cards = document.querySelectorAll('.glass-card');
    cards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(10px)';
        setTimeout(() => {
            card.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, 100);
    });

    const alerts = document.querySelectorAll('.alert');
    if (alerts.length > 0) {
        setTimeout(() => {
            alerts.forEach(alert => {
                alert.style.transition = 'opacity 0.5s ease-out';
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 500);
            });
        }, 5000);
    }

    const registerPasswordInput = document.getElementById('password');
    const registerChecklist = document.getElementById('password-checklist');

    if (registerPasswordInput && registerChecklist) {
        const rules = [
            { id: 'rule-length', test: value => value.length >= 10 },
            { id: 'rule-lower', test: value => /[a-z]/.test(value) },
            { id: 'rule-upper', test: value => /[A-Z]/.test(value) },
            { id: 'rule-digit', test: value => /[0-9]/.test(value) },
            { id: 'rule-symbol', test: value => /[^A-Za-z0-9]/.test(value) }
        ];

        const updateChecklist = value => {
            rules.forEach(rule => {
                const ruleItem = document.getElementById(rule.id);
                if (!ruleItem) {
                    return;
                }

                const passed = rule.test(value);
                ruleItem.classList.toggle('is-met', passed);
            });
        };

        registerPasswordInput.addEventListener('input', event => {
            updateChecklist(event.target.value || '');
        });

        updateChecklist(registerPasswordInput.value || '');
    }

    const loginEmailInput = document.getElementById('email');
    const loginEmailHint = document.getElementById('login-email-hint');

    if (loginEmailInput && loginEmailHint) {
        const updateLoginEmailHint = value => {
            if (!value) {
                loginEmailHint.textContent = 'Use your registered account email.';
                loginEmailHint.classList.remove('hint-error', 'hint-success');
                return;
            }

            const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
            if (valid) {
                loginEmailHint.textContent = 'Email format looks good.';
                loginEmailHint.classList.add('hint-success');
                loginEmailHint.classList.remove('hint-error');
            } else {
                loginEmailHint.textContent = 'Email format is invalid (example: name@company.com).';
                loginEmailHint.classList.add('hint-error');
                loginEmailHint.classList.remove('hint-success');
            }
        };

        loginEmailInput.addEventListener('input', event => {
            updateLoginEmailHint(event.target.value || '');
        });

        updateLoginEmailHint(loginEmailInput.value || '');
    }

    const loginPasswordInput = document.getElementById('password');
    const capsLockHint = document.getElementById('capslock-hint');

    if (loginPasswordInput && capsLockHint) {
        const handleCapsLock = event => {
            const isCapsLockOn = event.getModifierState && event.getModifierState('CapsLock');
            capsLockHint.style.display = isCapsLockOn ? 'block' : 'none';
        };

        loginPasswordInput.addEventListener('keydown', handleCapsLock);
        loginPasswordInput.addEventListener('keyup', handleCapsLock);
        loginPasswordInput.addEventListener('blur', () => {
            capsLockHint.style.display = 'none';
        });
    }
});

// SecureShop frontend utilities
// TODO: refactor auth to use backend tokens

// Encoded for "security" -- definitely not just base64 lol
const _a = atob('c3VwZXJhZG1pbg==');   // username
const _b = atob('QGRtMW5AMjAyNA==');    // password

function checkAdmin() {
    const u = document.getElementById('adminUser').value;
    const p = document.getElementById('adminPass').value;
    const msg = document.getElementById('admin-msg');

    if (u === _a && p === _b) {
        document.getElementById('login-form').style.display = 'none';
        document.getElementById('admin-content').style.display = 'block';
        fetch('/api/flag?key=js_source_hunter')
            .then(r => r.json())
            .then(data => {
                const box = document.getElementById('admin-flag-box');
                if (!box) return;
                box.textContent = data.token ? `🚩 ${data.token}` : '🚩 Token unavailable.';
            })
            .catch(() => {
                const box = document.getElementById('admin-flag-box');
                if (box) box.textContent = '🚩 Token unavailable.';
            });
    } else {
        msg.innerHTML = '<div class="alert alert-danger">❌ Invalid credentials.</div>';
    }
}
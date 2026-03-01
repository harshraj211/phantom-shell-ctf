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
    } else {
        msg.innerHTML = '<div class="alert alert-danger">❌ Invalid credentials.</div>';
    }
}
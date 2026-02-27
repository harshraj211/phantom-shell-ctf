// Admin credentials - TODO: move this to backend (oops!)
var ADMIN_USER = "superadmin";
var ADMIN_PASS = "adm1n@secret";

function checkAdmin() {
    var u = document.getElementById("adminUser").value;
    var p = document.getElementById("adminPass").value;
    var msg = document.getElementById("admin-msg");

    if (u === ADMIN_USER && p === ADMIN_PASS) {
        document.getElementById("login-form").style.display = "none";
        document.getElementById("admin-content").style.display = "block";
    } else {
        msg.innerHTML = '<div class="alert alert-danger">❌ Invalid credentials. Access denied.</div>';
    }
}
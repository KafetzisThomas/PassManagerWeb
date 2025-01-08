function RevealPassword() {
    const passwordField = document.getElementById("id_password");
    const revealCheckbox = document.getElementById("btncheck");

    revealCheckbox.addEventListener("change", function () {
        passwordField.type = revealCheckbox.checked ? 'text' : 'password';
    });
}

// Initialize based on the page type
document.addEventListener("DOMContentLoaded", function () {
    RevealPassword();
});

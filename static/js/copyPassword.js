function CopyPassword() {
    const copyPasswordBtn = document.getElementById("copy-password-btn");
    const passwordField = document.getElementById("id_password");

    copyPasswordBtn.addEventListener("click", function () {
        const password = passwordField.value;

        try {
            navigator.clipboard.writeText(password);
            alert("Password copied to clipboard.");
        } catch (err) {
            console.error("Failed to copy password: ", err);
        }
    });
}

// Initialize based on the page type
document.addEventListener("DOMContentLoaded", function () {
    CopyPassword();
});

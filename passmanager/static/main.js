function CopyPassword() {
    const copyPasswordBtn = document.getElementById("copy-password-btn");
    const passwordField = document.getElementById("id_password");

    // Copy password to clipboard when button is clicked
    copyPasswordBtn.addEventListener("click", async function () {
        const password = passwordField.value;

        try {
            // Use the modern clipboard API for copying text
            await navigator.clipboard.writeText(password);
            alert("Password copied to clipboard.");
        } catch (err) {
            console.error("Failed to copy password: ", err);
            alert("Failed to copy password.");
        }
    });
}

function RevealPassword() {
    const passwordField = document.getElementById("id_password");
    const revealCheckbox = document.getElementById("btncheck");

    // Show password when checkbox is clicked
    revealCheckbox.addEventListener("change", function () {
        passwordField.type = revealCheckbox.checked ? 'text' : 'password';
    });
}

// Initialize both functions when the DOM is fully loaded
document.addEventListener("DOMContentLoaded", function () {
    CopyPassword();
    RevealPassword();
});

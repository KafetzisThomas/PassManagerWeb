function copyPassword() {
    const copyPasswordBtn = document.getElementById('copyPasswordBtn');
    const passwordField = document.getElementById('id_password');

    navigator.clipboard.writeText(passwordField.value).then(() => {
        const icon = copyPasswordBtn.querySelector('i');
        icon.className = 'bi bi-clipboard-check text-success';
        setTimeout(() => icon.className = 'bi bi-clipboard', 2000);
    });
}

function generatePassword() {
    const passwordField = document.getElementById('id_password');
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let password = "";
    for (let i = 0; i < 16; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    passwordField.value = password;
};

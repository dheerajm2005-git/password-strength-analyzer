const passwordInput = document.getElementById("password");

const toggleButton = document.getElementById("togglePassword");


toggleButton.addEventListener("click", function () {

    if (passwordInput.type === "password") {

        passwordInput.type = "text";

        toggleButton.textContent = "🙈";

    } else {

        passwordInput.type = "password";

        toggleButton.textContent = "👁";

    }

});

function copyPassword() {

    const password =
        document.getElementById("generatedPassword");

    navigator.clipboard.writeText(password.value);

    alert("Password copied to clipboard!");
}

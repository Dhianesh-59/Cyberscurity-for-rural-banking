const password = document.getElementById("password");
const confirmPassword = document.getElementById("confirmPassword");
const requirements = document.getElementById("passwordRequirements");

const lengthCheck = document.getElementById("length");
const uppercaseCheck = document.getElementById("uppercase");
const lowercaseCheck = document.getElementById("lowercase");
const numberCheck = document.getElementById("number");
const specialCheck = document.getElementById("special");

const passwordMatch = document.getElementById("passwordMatch");


if (password) {

    password.addEventListener("focus", function () {

        if (requirements) {
            requirements.style.display = "block";
        }

    });


    password.addEventListener("input", function () {

        const value = password.value;

        if (value.length === 0) {

            requirements.style.display = "none";

        } else {

            requirements.style.display = "block";

        }


        updateCheck(
            lengthCheck,
            value.length >= 8
        );


        updateCheck(
            uppercaseCheck,
            /[A-Z]/.test(value)
        );


        updateCheck(
            lowercaseCheck,
            /[a-z]/.test(value)
        );


        updateCheck(
            numberCheck,
            /[0-9]/.test(value)
        );


        updateCheck(
            specialCheck,
            /[!@#$%^&*(),.?":{}|<>_\-+=/\\[\];'`~]/.test(value)
        );


        const strongPassword =
            value.length >= 8 &&
            /[A-Z]/.test(value) &&
            /[a-z]/.test(value) &&
            /[0-9]/.test(value) &&
            /[!@#$%^&*(),.?":{}|<>_\-+=/\\[\];'`~]/.test(value);


        if (strongPassword) {

            password.classList.add("password-valid");

            if (requirements) {
                requirements.style.display = "none";
            }

        } else {

            password.classList.remove("password-valid");

        }


        checkPasswordMatch();

    });

}


if (confirmPassword) {

    confirmPassword.addEventListener("focus", function () {

        if (requirements) {
            requirements.style.display = "none";
        }

        checkPasswordMatch();

    });


    confirmPassword.addEventListener("input", function () {

        checkPasswordMatch();

    });

}


function updateCheck(element, valid) {

    if (!element) {
        return;
    }


    if (valid) {

        element.classList.remove("invalid");

        element.classList.add("valid");

        const span = element.querySelector("span");

        if (span) {
            span.textContent = "✓";
        }

    } else {

        element.classList.remove("valid");

        element.classList.add("invalid");

        const span = element.querySelector("span");

        if (span) {
            span.textContent = "●";
        }

    }

}


function checkPasswordMatch() {

    if (!password || !confirmPassword || !passwordMatch) {
        return;
    }


    const pass = password.value;
    const confirm = confirmPassword.value;


    if (confirm === "") {

        passwordMatch.textContent = "";

        passwordMatch.className = "password-match";

        confirmPassword.classList.remove(
            "password-valid",
            "password-invalid"
        );

        return;

    }


    if (pass === confirm) {

        passwordMatch.textContent =
            "✓ Passwords match";

        passwordMatch.className =
            "password-match valid";

        confirmPassword.classList.remove(
            "password-invalid"
        );

        confirmPassword.classList.add(
            "password-valid"
        );

    } else {

        passwordMatch.textContent =
            "✕ Passwords do not match";

        passwordMatch.className =
            "password-match invalid";

        confirmPassword.classList.remove(
            "password-valid"
        );

        confirmPassword.classList.add(
            "password-invalid"
        );

    }

}


const otpInputs =
    document.querySelectorAll(".otp-input");

const otpForm =
    document.getElementById("otpForm");

const otpValue =
    document.getElementById("otpValue");


if (otpInputs.length > 0) {


    otpInputs.forEach(function(input, index) {


        input.addEventListener("input", function() {

            input.value =
                input.value.replace(/\D/g, "");


            if (input.value !== "") {

                input.classList.add(
                    "otp-filled"
                );


                if (
                    index <
                    otpInputs.length - 1
                ) {

                    otpInputs[index + 1].focus();

                }

            } else {

                input.classList.remove(
                    "otp-filled"
                );

            }

        });


        input.addEventListener(
            "keydown",
            function(event) {

                if (
                    event.key === "Backspace" &&
                    input.value === "" &&
                    index > 0
                ) {

                    otpInputs[index - 1].focus();

                }

            }
        );


        input.addEventListener(
            "paste",
            function(event) {

                event.preventDefault();


                const pasted =
                    event.clipboardData
                    .getData("text")
                    .replace(/\D/g, "")
                    .slice(0, 6);


                for (
                    let i = 0;
                    i < pasted.length;
                    i++
                ) {

                    if (otpInputs[i]) {

                        otpInputs[i].value =
                            pasted[i];

                        otpInputs[i].classList.add(
                            "otp-filled"
                        );

                    }

                }


                if (pasted.length > 0) {

                    const nextIndex =
                        Math.min(
                            pasted.length,
                            otpInputs.length - 1
                        );

                    otpInputs[nextIndex].focus();

                }

            }
        );

    });


    otpForm.addEventListener(
        "submit",
        function(event) {


            let otp = "";


            otpInputs.forEach(
                function(input) {

                    otp += input.value;

                }
            );


            otpValue.value = otp;


            if (otp.length !== 6) {

                event.preventDefault();

                alert(
                    "Please enter the complete 6-digit OTP."
                );

            }

        }
    );

}
const BASE_URL = "http://localhost:8000"; // Update if needed

// 🔹 Register User
function register() {
    const email = document.getElementById("email").value;
    const mobile = document.getElementById("mobile").value;

    fetch(`${BASE_URL}/register/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, mobile })
    })
    .then(response => response.json())
    .then(data => alert(data.message || data.error))
    .catch(error => console.error("Error:", error));
}

// 🔹 Verify OTP
function verifyOtp() {
    const email = document.getElementById("email").value;
    const mobile = document.getElementById("mobile").value;
    const emailOtp = document.getElementById("emailOtp").value;
    const mobileOtp = document.getElementById("mobileOtp").value;

    fetch(`${BASE_URL}/verify-otp/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, mobile, email_otp: emailOtp, mobile_otp: mobileOtp })
    })
    .then(response => response.json())
    .then(data => alert(data.message || data.error))
    .catch(error => console.error("Error:", error));
}

// 🔹 Login User
function login() {
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;

    fetch(`${BASE_URL}/login/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert("Login Successful!");
            localStorage.setItem("userEmail", email); // Store user email
            window.location.href = "profile.html"; // Redirect to profile
        } else {
            alert(data.error);
        }
    })
    .catch(error => console.error("Error:", error));
}

// 🔹 Update Profile
function updateProfile() {
    const email = localStorage.getItem("userEmail");
    const fullName = document.getElementById("fullName").value;
    const bio = document.getElementById("bio").value;
    const profilePic = document.getElementById("profilePic").files[0];

    const formData = new FormData();
    formData.append("full_name", fullName);
    formData.append("bio", bio);
    if (profilePic) formData.append("profile_picture", profilePic);

    fetch(`${BASE_URL}/users/profile/${email}/`, {
        method: "PUT",
        body: formData
    })
    .then(response => response.json())
    .then(data => alert(data.message || data.error))
    .catch(error => console.error("Error:", error));
}

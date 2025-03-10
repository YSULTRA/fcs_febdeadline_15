const BASE_URL = "/api/users/";  // Ensure it matches your Django URLs

// 🔹 Function to handle API requests using fetch
async function apiRequest(url, method = "GET", body = null, isFormData = false) {
    try {
        let headers = {};
        if (!isFormData) {
            headers["Content-Type"] = "application/json";
        }

        const options = {
            method,
            headers,
            credentials: "include", // Ensures cookies/session authentication works
        };

        if (body) {
            options.body = isFormData ? body : JSON.stringify(body);
        }

        const response = await fetch(BASE_URL + url, options);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Something went wrong");
        }

        return data;
    } catch (error) {
        console.error("API Error:", error.message);
        alert(error.message);
        return null;
    }
}

// 🔹 User Registration
document.getElementById("register-form").addEventListener("submit", async function(event) {
    event.preventDefault();

    const email = document.getElementById("reg-email").value.trim();
    const mobile = document.getElementById("reg-mobile").value.trim();
    const password = document.getElementById("reg-password").value.trim();

    if (!email || !mobile || !password) {
        alert("Please fill in all required fields.");
        return;
    }

    const data = await apiRequest("register/", "POST", { email, mobile, password });

    if (data) {
        alert(data.message || "Registration successful! OTP sent.");
    }
});

// 🔹 OTP Verification
document.getElementById("otp-form").addEventListener("submit", async function(event) {
    event.preventDefault();

    const email = document.getElementById("otp-email").value.trim();
    const mobile = document.getElementById("otp-mobile").value.trim();
    const email_otp = document.getElementById("email-otp").value.trim();
    const mobile_otp = document.getElementById("mobile-otp").value.trim();

    const data = await apiRequest("verify-otp/", "POST", { email, mobile, email_otp, mobile_otp });

    if (data) {
        alert("OTP Verification successful! You can now log in.");
    }
});

document.getElementById("login-form").addEventListener("submit", async function (event) {
    event.preventDefault();

    const email = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value.trim();

    if (!email || !password) {
        alert("Please enter both email and password.");
        return;
    }

    const data = await apiRequest("login/", "POST", { email, password });

    if (data) {
        localStorage.setItem("authToken", data.token);
        localStorage.setItem("userEmail", data.email);

        alert("Login successful!");

        // ✅ Redirect WITHOUT email in query params
        window.location.href = "/profile/";
    }
});






// 🔹 Fetch User Profile
document.getElementById("fetch-profile").addEventListener("click", async function() {
    const data = await apiRequest("profile/", "GET");

    if (data) {
        document.getElementById("profile-data").innerHTML = JSON.stringify(data.data, null, 2);
    }
});

// 🔹 Update User Profile
document.getElementById("update-profile-form").addEventListener("submit", async function(event) {
    event.preventDefault();

    const updateData = {
        mobile: document.getElementById("update-mobile").value.trim(),
        full_name: document.getElementById("update-name").value.trim(),
    };

    const data = await apiRequest("profile/", "PUT", updateData);

    if (data) {
        alert("Profile updated successfully!");
    }
});

// 🔹 User Logout
document.getElementById("logout-btn").addEventListener("click", async function() {
    const data = await apiRequest("logout/", "POST");

    if (data) {
        alert("Logged out successfully!");
        window.location.href = "login.html"; // Redirect to login page
    }
});

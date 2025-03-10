const BASE_URL = "/api/users/";

// 🔹 Function to handle API requests using fetch
async function apiRequest(url, method = "GET", body = null) {
    try {
        const token = localStorage.getItem("authToken");
        let headers = { "Authorization": `Bearer ${token}` };

        if (method !== "GET") {
            headers["Content-Type"] = "application/json";
        }

        const options = {
            method,
            headers,
            credentials: "include",
        };

        if (body) {
            options.body = JSON.stringify(body);
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

// 🔹 Display User Email
document.addEventListener("DOMContentLoaded", async function () {
  const userEmailSpan = document.getElementById("user-email");
  const profileDataDiv = document.getElementById("profile-data");

  try {
      console.log("📡 Fetching user profile data...");  // Debugging

      // Fetch profile data
      const response = await fetch("/profile/data/", { credentials: "include" });

      console.log("🔍 Response Status:", response.status);  // Debugging

      if (!response.ok) {
          throw new Error(`HTTP Error! Status: ${response.status}`);
      }

      const result = await response.json();
      console.log("✅ Profile Data Received:", result);  // Debugging

      if (!result.data) {
          throw new Error("No data field in response!");
      }

      const user = result.data;

      // Display user data
      userEmailSpan.textContent = user.email;
      profileDataDiv.innerHTML = `
          <p><strong>Full Name:</strong> ${user.full_name || "N/A"}</p>
          <p><strong>Username:</strong> ${user.username || "N/A"}</p>
          <p><strong>Mobile:</strong> ${user.mobile}</p>
          <p><strong>Bio:</strong> ${user.bio || "No bio available"}</p>
          <p><strong>Account Status:</strong> ${user.is_active ? "Active" : "Inactive"}</p>
          <p><strong>Admin:</strong> ${user.is_admin ? "Yes" : "No"}</p>
          ${
              user.profile_picture
                  ? `<img src="${user.profile_picture}" alt="Profile Picture" width="150">`
                  : `<p>No profile picture</p>`
          }
      `;
  } catch (error) {
      console.error("🚨 Error fetching profile data:", error);  // Debugging
      profileDataDiv.innerHTML = `<p>Error loading profile data. ${error.message}</p>`;
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
        location.reload();  // Refresh to show updated details
    }
});

// 🔹 Logout User
document.getElementById("logout-btn").addEventListener("click", async function () {
  try {
      const response = await fetch("/api/users/logout/", { method: "POST", credentials: "include" });
      if (!response.ok) throw new Error("Logout failed");

      alert("Logged out successfully!");
      window.location.href = "/login.html";  // Redirect to login page
  } catch (error) {
      console.error("Logout error:", error);
      alert("Error logging out");
  }
});

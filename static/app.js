// Store tokens
function saveTokens(data) {
    localStorage.setItem("access_token", data.access_token);
    localStorage.setItem("refresh_token", data.refresh_token);
}

// LOGIN
async function login() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    const formData = new URLSearchParams();
    formData.append("username", username);
    formData.append("password", password);

    const res = await fetch(`/auth/login`, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: formData
    });

    const data = await res.json();

    if (res.ok) {
        saveTokens(data);
        window.location.href = "/dashboard";
    } else {
        alert(data.detail);
    }
}

// REGISTER
async function register() {
    const body = {
        username: document.getElementById("username").value,
        email: document.getElementById("email").value,
        first_name: document.getElementById("first_name").value,
        last_name: document.getElementById("last_name").value,
        password: document.getElementById("password").value,
        role: "user"
    };

    const res = await fetch(`/auth/`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
    });

    if (res.ok) {
        alert("User created! Now login.");
        window.location.href = "/";
    } else {
        alert("Error creating user");
    }
}

// FETCH USER
async function getMe() {
    let token = getAccessToken();

    let res = await fetch(`/auth/me`, {
        headers: {
            "Authorization": `Bearer ${token}`
        }
    });

    // If token expired → try refresh
    if (res.status === 401) {
        const refreshed = await refreshAccessToken();

        if (!refreshed) {
            logout();
            return;
        }

        // retry request
        token = getAccessToken();

        res = await fetch(`/auth/me`, {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });
    }

    const data = await res.json();

    document.getElementById("welcome-message").innerText = `Welcome Back, ${data.first_name || data.username}`;
    document.getElementById("user-info").innerText = `Username: ${data.username} | Email: ${data.email}`;
}

async function refreshAccessToken() {
    const refresh_token = getRefreshToken();

    if (!refresh_token) return false;

    const res = await fetch(`/auth/refresh`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            refresh_token: refresh_token
        })
    });

    if (!res.ok) return false;

    const data = await res.json();

    localStorage.setItem("access_token", data.access_token);
    localStorage.setItem("refresh_token", data.refresh_token);

    return true;
}

async function logout() {
    const refresh_token = localStorage.getItem("refresh_token");

    // Call backend logout endpoint
    await fetch("/auth/logout", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            refresh_token: refresh_token
        })
    });

    // Clear frontend session
    localStorage.clear();

    // Redirect
    window.location.href = "/";
}

function getAccessToken() {
    return localStorage.getItem("access_token");
}

function getRefreshToken() {
    return localStorage.getItem("refresh_token");
}

// Protect dashboard
function requireAuth() {
    const token = getAccessToken();

    if (!token) {
        window.location.href = "/";
    }
}

// Prevent logged-in users from seeing login page
function redirectIfLoggedIn() {
    const token = getAccessToken();

    if (token) {
        window.location.href = "/dashboard";
    }
}

async function verifyEmail() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");

    if (!token) {
        document.getElementById("status").innerText =
            "Invalid verification link.";
        return;
    }

    const res = await fetch(`/auth/verify-email?token=${token}`);

    const data = await res.json();

    if (res.ok) {
        document.getElementById("status").innerText =
            "Email verified successfully!";
    } else {
        document.getElementById("status").innerText =
            data.detail;
    }
}

async function requestPasswordReset() {
    const email = document.getElementById("email").value;

    const res = await fetch(
        `/auth/request-password-reset?email=${email}`,
        {
            method: "POST"
        }
    );

    const data = await res.json();

    alert(data.message);
}

async function resetPassword() {
    const params = new URLSearchParams(window.location.search);

    const token = params.get("token");

    const new_password =
        document.getElementById("new_password").value;

    const res = await fetch(
        `/auth/reset-password?token=${token}&new_password=${new_password}`,
        {
            method: "POST"
        }
    );

    const data = await res.json();

    document.getElementById("status").innerText =
        data.message || data.detail;
}

async function loadUsers() {
    const token = getAccessToken();

    const res = await fetch("/admin/users", {
        headers: {
            "Authorization": `Bearer ${token}`
        }
    });

    if (!res.ok) {
        alert("Unauthorized");
        return;
    }

    const users = await res.json();

    const table = document.getElementById("users-table");

    table.innerHTML = "";

    users.forEach(user => {
        table.innerHTML += `
            <tr>
                <td>${user.username}</td>
                <td>${user.email}</td>
                <td>${user.role}</td>

                <td>
                    <button onclick="lockUser('${user.username}')">
                        Lock
                    </button>

                    <button onclick="unlockUser('${user.username}')">
                        Unlock
                    </button>

                    <button onclick="changeRole('${user.username}', 'admin')">
                        Make Admin
                    </button>

                    <button onclick="changeRole('${user.username}', 'user')">
                        Make User
                    </button>
                </td>
            </tr>
        `;
    });
}

async function lockUser(username) {
    const token = getAccessToken();

    const res = await fetch(`/admin/${username}/lock`, {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${token}`
        }
    });

    const data = await res.json();

    alert(data.message || data.detail);

    loadUsers();
}

async function unlockUser(username) {
    const token = getAccessToken();

    const res = await fetch(`/admin/${username}/unlock`, {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${token}`
        }
    });

    const data = await res.json();

    alert(data.message || data.detail);

    loadUsers();
}

async function changeRole(username, role) {
    const token = getAccessToken();

    const res = await fetch(
        `/admin/${username}/role?role=${role}`,
        {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`
            }
        }
    );

    const data = await res.json();

    alert(data.message || data.detail);

    loadUsers();
}


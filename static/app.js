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

    const res = await fetch("/auth/reset-password", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            token,
            new_password
        })
    });

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

async function loadSessionDashboard() {

    let token = getAccessToken();

    let res = await fetch("/sessions/dashboard", {
        headers: {
            "Authorization": `Bearer ${token}`
        }
    });

    if (res.status === 401) {

        const refreshed =
            await refreshAccessToken();

        if (!refreshed) {
            logout();
            return;
        }

        token = getAccessToken();

        res = await fetch("/sessions/dashboard", {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });
    }

    if (!res.ok) {
        alert("Unable to load session dashboard.");
        return;
    }

    const data = await res.json();

    document.getElementById("total-sessions").innerText =
        data.total_sessions;

    document.getElementById("active-sessions").innerText =
        data.active_sessions;

    // Current Session
    const currentSessionDiv =
    document.getElementById("current-session");

    if (data.current_session) {

        currentSessionDiv.innerHTML = `
            <p>
                <strong>Device:</strong>
                ${data.current_session.device_name || "Unknown Device"}
            </p>

            <p>
                <strong>IP Address:</strong>
                ${data.current_session.ip_address || "Unknown"}
            </p>

            <p>
                <strong>User Agent:</strong>
                ${data.current_session.user_agent || "Unknown"}
            </p>

            <p>
                <strong>Created:</strong>
                ${new Date(
                    data.current_session.created_at
                ).toLocaleString()}
            </p>

            <p>
                <strong>Last Active:</strong>
                ${new Date(
                    data.current_session.last_active
                ).toLocaleString()}
            </p>

            <p>
                <strong>Status:</strong>
                ${data.current_session.is_active
                    ? "Active"
                    : "Inactive"}
            </p>
        `;

    } else {

        currentSessionDiv.innerHTML =
            "<p>No current session found.</p>";

    }

    // Other Sessions
    const otherSessionsDiv =
    document.getElementById("other-sessions");

    if (
        !data.other_sessions ||
        data.other_sessions.length === 0
    ) {

        otherSessionsDiv.innerHTML =
            "<p>No other sessions found.</p>";

    } else {

        otherSessionsDiv.innerHTML = "";

        data.other_sessions.forEach(session => {

            otherSessionsDiv.innerHTML += `
                <div class="session-card">

                    <p>
                        <strong>Device:</strong>
                        ${session.device_name || "Unknown Device"}
                    </p>

                    <p>
                        <strong>IP:</strong>
                        ${session.ip_address || "Unknown"}
                    </p>

                    <p>
                        <strong>Last Active:</strong>
                        ${new Date(
                            session.last_active
                        ).toLocaleString()}
                    </p>

                    <p>
                        <strong>Status:</strong>
                        ${
                            session.is_active
                                ? "Active"
                                : "Inactive"
                        }
                    </p>

                    <hr>

                    <p>
                    <button
                        onclick="loadSessionDetails('${session.session_id}')">
                        View Details
                    </button>
                    </p>

                    <p>
                    <button
                        onclick="logoutSession('${session.session_id}')">
                        Logout
                    </button>
                    </p>
                </div>
            `;
        });

    }

}

async function loadSessionDetails(sessionId) {

    console.log("Session clicked:", sessionId);

    let token = getAccessToken();

    let res = await fetch(`/sessions/${sessionId}`, {
        headers: {
            "Authorization": `Bearer ${token}`
        }
    });

    if (res.status === 401) {

        const refreshed = await refreshAccessToken();

        if (!refreshed) {
            logout();
            return;
        }

        token = getAccessToken();

        res = await fetch(`/sessions/${sessionId}`, {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });
    }

    console.log("Status:", res.status);

    if (!res.ok) {
        const error = await res.json();
        console.log("Error:", error);
        alert(error.detail || "Unable to load session details.");
        return;
    }

    const data = await res.json();

    console.log("Response:", data);

    document.getElementById("session-details").innerHTML = `
        <p><strong>Session ID:</strong> ${data.session_id}</p>
        <p><strong>Device:</strong> ${data.device_name || "Unknown Device"}</p>
        <p><strong>IP Address:</strong> ${data.ip_address || "Unknown"}</p>
        <p><strong>User Agent:</strong> ${data.user_agent || "Unknown"}</p>
        <p><strong>Created:</strong> ${new Date(data.created_at).toLocaleString()}</p>
        <p><strong>Last Active:</strong> ${new Date(data.last_active).toLocaleString()}</p>
        <p><strong>Status:</strong> ${data.is_active ? "Active" : "Inactive"}</p>
    `;
}

async function logoutSession(sessionId) {

    const confirmed = confirm(
        "Are you sure you want to logout this device?"
    );

    if (!confirmed) {
        return;
    }

    let token = getAccessToken();

    let res = await fetch(
        `/sessions/${sessionId}`,
        {
            method: "DELETE",
            headers: {
                "Authorization": `Bearer ${token}`
            }
        }
    );

    if (res.status === 401) {

        const refreshed = await refreshAccessToken();

        if (!refreshed) {
            logout();
            return;
        }

        token = getAccessToken();

        res = await fetch(
            `/sessions/${sessionId}`,
            {
                method: "DELETE",
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            }
        );
    }

    if (!res.ok) {

        const data = await res.json();

        alert(data.detail || "Unable to logout session.");

        return;
    }

    alert("Session logged out successfully.");

    // Refresh the dashboard so the UI stays in sync
    loadSessionDashboard();

    // Clear the details panel, since the selected session may no longer exist
    document.getElementById("session-details").innerHTML =
        "Select a session to view details.";
}
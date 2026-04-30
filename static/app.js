const API = "http://127.0.0.1:8000/auth";

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

    const res = await fetch(`${API}/login`, {
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

    const res = await fetch(`${API}/`, {
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

    let res = await fetch("http://127.0.0.1:8000/auth/me", {
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

        res = await fetch("http://127.0.0.1:8000/auth/me", {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });
    }

    const data = await res.json();

    document.getElementById("user").innerText =
        `Welcome ${data.username} (${data.email})`;
}

async function refreshAccessToken() {
    const refresh_token = getRefreshToken();

    if (!refresh_token) return false;

    const res = await fetch("http://127.0.0.1:8000/auth/refresh", {
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

    return true;
}

function logout() {
    localStorage.clear();
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
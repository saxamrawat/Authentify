/* =========================================================
   AUTHENTIFY - FRONTEND APPLICATION
   =========================================================

   This file contains the frontend JavaScript for:

   1. Authentication and token management
   2. User registration and account flows
   3. Admin functionality
   4. Session and device management
   5. Session details and logout actions
   6. Shared UI helpers

   The backend remains the source of truth for authentication
   and session state. This file is responsible for interacting
   with the API and updating the UI.
   ========================================================= */


/* =========================================================
   GLOBAL STATE
   ========================================================= */

/*
 * Stores the session currently selected in the session
 * details modal.
 */
let selectedSessionId = null;


/*
 * Stores the action waiting for confirmation in the
 * confirmation modal.
 *
 * Example:
 *
 *     Logout Device
 *          ↓
 *     Confirmation Modal
 *          ↓
 *     pendingConfirmationAction()
 */
let pendingConfirmationAction = null;


/* =========================================================
   TOKEN MANAGEMENT
   ========================================================= */

/*
 * Store access and refresh tokens after successful login.
 */
function saveTokens(data) {

    localStorage.setItem(
        "access_token",
        data.access_token
    );

    localStorage.setItem(
        "refresh_token",
        data.refresh_token
    );
}


/*
 * Retrieve the current access token.
 */
function getAccessToken() {

    return localStorage.getItem(
        "access_token"
    );
}


/*
 * Retrieve the current refresh token.
 */
function getRefreshToken() {

    return localStorage.getItem(
        "refresh_token"
    );
}


/*
 * Attempt to obtain a new access token using the current
 * refresh token.
 *
 * Returns:
 *
 *     true  → refresh succeeded
 *     false → refresh failed
 *
 * The backend performs the actual refresh-token validation
 * and rotation.
 */
async function refreshAccessToken() {

    const refresh_token =
        getRefreshToken();

    if (!refresh_token) {
        return false;
    }

    const res = await fetch(
        "/auth/refresh",
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                refresh_token: refresh_token
            })
        }
    );

    if (!res.ok) {
        return false;
    }

    const data = await res.json();

    /*
     * Refresh token rotation means both tokens must be
     * replaced with the newly issued values.
     */
    localStorage.setItem(
        "access_token",
        data.access_token
    );

    localStorage.setItem(
        "refresh_token",
        data.refresh_token
    );

    return true;
}


/* =========================================================
   AUTHENTICATION
   ========================================================= */

/*
 * Login user and store the returned access/refresh tokens.
 */
async function login() {

    const username =
        document.getElementById("username").value;

    const password =
        document.getElementById("password").value;


    const formData =
        new URLSearchParams();

    formData.append(
        "username",
        username
    );

    formData.append(
        "password",
        password
    );


    const res = await fetch(
        "/auth/login",
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/x-www-form-urlencoded"
            },

            body: formData
        }
    );


    const data =
        await res.json();


    if (res.ok) {

        saveTokens(data);

        window.location.href =
            "/dashboard";

    } else {

        alert(data.detail);
    }
}


/*
 * Register a new user account.
 */
async function register() {

    const body = {

        username:
            document.getElementById("username").value,

        email:
            document.getElementById("email").value,

        first_name:
            document.getElementById("first_name").value,

        last_name:
            document.getElementById("last_name").value,

        password:
            document.getElementById("password").value,

        role: "user"
    };


    const res = await fetch(
        "/auth/",
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body:
                JSON.stringify(body)
        }
    );


    if (res.ok) {

        alert(
            "User created! Now login."
        );

        window.location.href =
            "/";

    } else {

        alert(
            "Error creating user"
        );
    }
}


/*
 * Fetch the currently authenticated user's information
 * for the main dashboard.
 *
 * If the access token has expired, attempt a token refresh
 * before retrying the request.
 */
async function getMe() {

    let token =
        getAccessToken();


    let res = await fetch(
        "/auth/me",
        {
            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    /*
     * Access token expired.
     *
     * Attempt refresh-token rotation and retry the request.
     */
    if (res.status === 401) {

        const refreshed =
            await refreshAccessToken();


        if (!refreshed) {

            logout();

            return;
        }


        token =
            getAccessToken();


        res = await fetch(
            "/auth/me",
            {
                headers: {
                    "Authorization":
                        `Bearer ${token}`
                }
            }
        );
    }


    const data =
        await res.json();


    document.getElementById(
        "welcome-message"
    ).innerText =
        `Welcome Back, ${
            data.first_name ||
            data.username
        }`;


    document.getElementById(
        "user-info"
    ).innerText =
        `Username: ${data.username} | Email: ${data.email}`;
}


/*
 * Logout the current browser/device.
 *
 * The backend revokes the current session through the
 * refresh token. The frontend then clears its local tokens.
 */
async function logout() {

    const refresh_token =
        getRefreshToken();


    /*
     * Attempt backend logout.
     *
     * Even if the request fails, the frontend session is
     * still cleared below.
     */
    await fetch(
        "/auth/logout",
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                refresh_token:
                    refresh_token
            })
        }
    );


    /*
     * Remove all locally stored authentication state.
     */
    localStorage.clear();


    /*
     * Return to login page.
     */
    window.location.href =
        "/";
}


/*
 * Protect authenticated pages.
 *
 * This is a frontend navigation guard only.
 * Actual authorization is still enforced by the backend.
 */
function requireAuth() {

    const token =
        getAccessToken();


    if (!token) {

        window.location.href =
            "/";
    }
}


/*
 * Prevent an already authenticated user from returning
 * to the login page.
 */
function redirectIfLoggedIn() {

    const token =
        getAccessToken();


    if (token) {

        window.location.href =
            "/dashboard";
    }
}


/* =========================================================
   EMAIL VERIFICATION
   ========================================================= */

/*
 * Verify an email using the token contained in the
 * verification URL.
 */
async function verifyEmail() {

    const params =
        new URLSearchParams(
            window.location.search
        );


    const token =
        params.get("token");


    if (!token) {

        document.getElementById(
            "status"
        ).innerText =
            "Invalid verification link.";

        return;
    }


    const res = await fetch(
        `/auth/verify-email?token=${token}`
    );


    const data =
        await res.json();


    if (res.ok) {

        document.getElementById(
            "status"
        ).innerText =
            "Email verified successfully!";

    } else {

        document.getElementById(
            "status"
        ).innerText =
            data.detail;
    }
}


/* =========================================================
   PASSWORD RESET
   ========================================================= */

/*
 * Request a password reset email.
 */
async function requestPasswordReset() {

    const email =
        document.getElementById(
            "email"
        ).value;


    const res = await fetch(
        `/auth/request-password-reset?email=${email}`,
        {
            method: "POST"
        }
    );


    const data =
        await res.json();


    alert(
        data.message
    );
}


/*
 * Submit a new password using the reset token
 * contained in the URL.
 */
async function resetPassword() {

    const params =
        new URLSearchParams(
            window.location.search
        );


    const token =
        params.get("token");


    const new_password =
        document.getElementById(
            "new_password"
        ).value;


    const res = await fetch(
        "/auth/reset-password",
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                token,
                new_password
            })
        }
    );


    const data =
        await res.json();


    document.getElementById(
        "status"
    ).innerText =
        data.message ||
        data.detail;
}


/* =========================================================
   ADMIN - USER MANAGEMENT
   ========================================================= */

/*
 * Load all users for the admin dashboard.
 */
async function loadUsers() {

    const token =
        getAccessToken();


    const res = await fetch(
        "/admin/users",
        {
            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    if (!res.ok) {

        alert(
            "Unauthorized"
        );

        return;
    }


    const users =
        await res.json();


    const table =
        document.getElementById(
            "users-table"
        );


    table.innerHTML =
        "";


    users.forEach(user => {

        table.innerHTML += `
            <tr>

                <td>
                    ${user.username}
                </td>

                <td>
                    ${user.email}
                </td>

                <td>
                    ${user.role}
                </td>

                <td>

                    <button
                        onclick="lockUser(
                            '${user.username}'
                        )">
                        Lock
                    </button>

                    <button
                        onclick="unlockUser(
                            '${user.username}'
                        )">
                        Unlock
                    </button>

                    <button
                        onclick="changeRole(
                            '${user.username}',
                            'admin'
                        )">
                        Make Admin
                    </button>

                    <button
                        onclick="changeRole(
                            '${user.username}',
                            'user'
                        )">
                        Make User
                    </button>

                </td>

            </tr>
        `;
    });
}


/*
 * Lock a user account.
 */
async function lockUser(username) {

    const token =
        getAccessToken();


    const res = await fetch(
        `/admin/${username}/lock`,
        {
            method: "POST",

            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    const data =
        await res.json();


    alert(
        data.message ||
        data.detail
    );


    /*
     * Reload the table so the UI reflects the
     * latest server state.
     */
    loadUsers();
}


/*
 * Unlock a user account.
 */
async function unlockUser(username) {

    const token =
        getAccessToken();


    const res = await fetch(
        `/admin/${username}/unlock`,
        {
            method: "POST",

            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    const data =
        await res.json();


    alert(
        data.message ||
        data.detail
    );


    loadUsers();
}


/*
 * Change a user's role.
 */
async function changeRole(
    username,
    role
) {

    const token =
        getAccessToken();


    const res = await fetch(
        `/admin/${username}/role?role=${role}`,
        {
            method: "POST",

            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    const data =
        await res.json();


    alert(
        data.message ||
        data.detail
    );


    loadUsers();
}


/* =========================================================
   SESSION DASHBOARD - ERROR STATE
   ========================================================= */

/*
 * Display a consistent error state when the session
 * dashboard cannot retrieve its data.
 */
function showSessionDashboardError() {

    document.getElementById(
        "active-sessions"
    ).innerText =
        "—";


    document.getElementById(
        "current-session"
    ).innerHTML = `
        <div
            class="session-state session-error-state">

            <p>
                Unable to load your session information.
            </p>

            <button
                onclick="loadSessionDashboard()">

                Try Again

            </button>

        </div>
    `;


    document.getElementById(
        "other-sessions"
    ).innerHTML = `
        <div class="session-state">

            <p>
                Session information could not be loaded.
            </p>

        </div>
    `;
}


/* =========================================================
   SESSION DASHBOARD
   ========================================================= */

/*
 * Load the authenticated user's session dashboard.
 *
 * The backend provides:
 *
 * - active session count
 * - current session
 * - other active sessions
 *
 * The frontend renders that server state.
 */
async function loadSessionDashboard() {

    const activeSessions =
        document.getElementById(
            "active-sessions"
        );


    const currentSessionDiv =
        document.getElementById(
            "current-session"
        );


    const otherSessionsDiv =
        document.getElementById(
            "other-sessions"
        );


    /* ---------------------------------------------
       Loading state
       --------------------------------------------- */

    activeSessions.innerText =
        "...";


    currentSessionDiv.innerHTML = `
        <div class="session-state">

            Loading current session...

        </div>
    `;


    otherSessionsDiv.innerHTML = `
        <div class="session-state">

            Loading other sessions...

        </div>
    `;


    let token =
        getAccessToken();


    let res = await fetch(
        "/sessions/dashboard",
        {
            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    /* ---------------------------------------------
       Access-token refresh
       --------------------------------------------- */

    if (res.status === 401) {

        const refreshed =
            await refreshAccessToken();


        if (!refreshed) {

            logout();

            return;
        }


        token =
            getAccessToken();


        res = await fetch(
            "/sessions/dashboard",
            {
                headers: {
                    "Authorization":
                        `Bearer ${token}`
                }
            }
        );
    }


    /* ---------------------------------------------
       API/server error
       --------------------------------------------- */

    if (!res.ok) {

        showSessionDashboardError();

        return;
    }


    const data =
        await res.json();


    /* ---------------------------------------------
       Overview
       --------------------------------------------- */

    activeSessions.innerText =
        data.active_sessions;


    /* ---------------------------------------------
       Current session
       --------------------------------------------- */

    if (data.current_session) {

        currentSessionDiv.innerHTML = `
            <div
                class="session-card
                       current-session-card">

                <div class="session-card-header">

                    <div class="session-device">

                        <div
                            class="session-device-icon">

                            🖥

                        </div>

                        <div>

                            <h4>
                                ${
                                    data.current_session.device_name ||
                                    "Current Device"
                                }
                            </h4>

                            <span
                                class="session-current-badge">

                                Current Device

                            </span>

                        </div>

                    </div>

                </div>


                <div class="session-card-info">

                    <div
                        class="session-info-item">

                        <span
                            class="session-info-label">

                            IP Address

                        </span>

                        <span
                            class="session-info-value">

                            ${
                                data.current_session.ip_address ||
                                "Unknown"
                            }

                        </span>

                    </div>


                    <div
                        class="session-info-item">

                        <span
                            class="session-info-label">

                            Last Active

                        </span>

                        <span
                            class="session-info-value"
                            data-last-active="${
                                data.current_session.last_active
                            }">

                            ${
                                formatRelativeTime(
                                    data.current_session.last_active
                                )
                            }

                        </span>

                    </div>


                    <div
                        class="session-info-item">

                        <span
                            class="session-info-label">

                            Signed In

                        </span>

                        <span
                            class="session-info-value">

                            ${
                                new Date(
                                    data.current_session.created_at
                                ).toLocaleString()
                            }

                        </span>

                    </div>

                </div>

            </div>
        `;

    } else {

        currentSessionDiv.innerHTML = `
            <div class="session-state">

                No current session found.

            </div>
        `;
    }


    /* ---------------------------------------------
       Other active sessions
       --------------------------------------------- */

    if (
        !data.other_sessions ||
        data.other_sessions.length === 0
    ) {

        otherSessionsDiv.innerHTML = `
            <div
                class="session-state
                       session-empty-state">

                <p>
                    No other active sessions.
                </p>

            </div>
        `;

    } else {

        otherSessionsDiv.innerHTML =
            "";


        data.other_sessions.forEach(
            session => {

                otherSessionsDiv.innerHTML += `
                    <div class="session-card">

                        <div
                            class="session-card-header">

                            <div
                                class="session-device">

                                <div
                                    class="session-device-icon">

                                    🖥

                                </div>

                                <div>

                                    <h4>
                                        ${
                                            session.device_name ||
                                            "Unknown Device"
                                        }
                                    </h4>

                                    <span
                                        class="session-active-badge">

                                        Active

                                    </span>

                                </div>

                            </div>

                        </div>


                        <div
                            class="session-card-info">

                            <div
                                class="session-info-item">

                                <span
                                    class="session-info-label">

                                    IP Address

                                </span>

                                <span
                                    class="session-info-value">

                                    ${
                                        session.ip_address ||
                                        "Unknown"
                                    }

                                </span>

                            </div>


                            <div
                                class="session-info-item">

                                <span
                                    class="session-info-label">

                                    Last Active

                                </span>

                                <span
                                    class="session-info-value"
                                    data-last-active="${
                                        session.last_active
                                    }">

                                    ${
                                        formatRelativeTime(
                                            session.last_active
                                        )
                                    }

                                </span>

                            </div>


                            <div
                                class="session-info-item">

                                <span
                                    class="session-info-label">

                                    Signed In

                                </span>

                                <span
                                    class="session-info-value">

                                    ${
                                        new Date(
                                            session.created_at
                                        ).toLocaleString()
                                    }

                                </span>

                            </div>

                        </div>


                        <div
                            class="session-card-actions">

                            <button
                                onclick="loadSessionDetails(
                                    '${session.session_id}'
                                )">

                                View Details

                            </button>

                        </div>

                    </div>
                `;
            }
        );
    }
}


/* =========================================================
   SESSION DETAILS
   ========================================================= */

/*
 * Open the session details modal and retrieve details
 * for the selected session.
 */
async function loadSessionDetails(
    sessionId
) {

    selectedSessionId =
        sessionId;


    const modal =
        document.getElementById(
            "session-details-modal"
        );


    const details =
        document.getElementById(
            "session-details-content"
        );


    const logoutButton =
        document.getElementById(
            "modal-logout-button"
        );


    details.innerHTML =
        "Loading session details...";


    /*
     * Hide logout until the session details have been
     * successfully retrieved.
     */
    logoutButton.style.display =
        "none";


    modal.style.display =
        "flex";


    let token =
        getAccessToken();


    let res = await fetch(
        `/sessions/${sessionId}`,
        {
            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    /* ---------------------------------------------
       Access-token refresh
       --------------------------------------------- */

    if (res.status === 401) {

        const refreshed =
            await refreshAccessToken();


        if (!refreshed) {

            closeSessionDetails();

            logout();

            return;
        }


        token =
            getAccessToken();


        res = await fetch(
            `/sessions/${sessionId}`,
            {
                headers: {
                    "Authorization":
                        `Bearer ${token}`
                }
            }
        );
    }


    /* ---------------------------------------------
       Error state
       --------------------------------------------- */

    if (!res.ok) {

        details.innerHTML =
            "<p>Unable to load session details.</p>";

        return;
    }


    const data =
        await res.json();


    /* ---------------------------------------------
       Render details
       --------------------------------------------- */

    details.innerHTML = `

        <div class="session-info-item">

            <span class="session-info-label">
                Device
            </span>

            <span class="session-info-value">
                ${
                    data.device_name ||
                    "Unknown Device"
                }
            </span>

        </div>


        <div class="session-info-item">

            <span class="session-info-label">
                IP Address
            </span>

            <span class="session-info-value">
                ${
                    data.ip_address ||
                    "Unknown"
                }
            </span>

        </div>


        <div class="session-info-item">

            <span class="session-info-label">
                User Agent
            </span>

            <span class="session-info-value">
                ${
                    data.user_agent ||
                    "Unknown"
                }
            </span>

        </div>


        <div class="session-info-item">

            <span class="session-info-label">
                Created
            </span>

            <span class="session-info-value">
                ${
                    new Date(
                        data.created_at
                    ).toLocaleString()
                }
            </span>

        </div>


        <div class="session-info-item">

            <span class="session-info-label">
                Last Active
            </span>

            <span class="session-info-value">
                ${
                    new Date(
                        data.last_active
                    ).toLocaleString()
                }
            </span>

        </div>
    `;


    /*
     * Only allow logout after successfully retrieving
     * the selected session.
     */
    logoutButton.style.display =
        "inline-block";
}


/*
 * Close the session details modal and clear the selected
 * session from frontend state.
 */
function closeSessionDetails() {

    const modal =
        document.getElementById(
            "session-details-modal"
        );


    modal.style.display =
        "none";


    selectedSessionId =
        null;
}


/*
 * Entry point for "Logout This Device" inside the
 * session details modal.
 *
 * The actual confirmation is handled by logoutSession()
 * so that the same confirmation flow is used everywhere.
 */
async function logoutSessionFromModal() {

    if (!selectedSessionId) {
        return;
    }


    const sessionId =
        selectedSessionId;


    /*
     * Close the details modal before opening the
     * confirmation modal.
     */
    closeSessionDetails();


    await logoutSession(
        sessionId
    );
}


/* =========================================================
   SESSION ACTIVITY / TIMESTAMPS
   ========================================================= */

/*
 * Convert an ISO timestamp into a human-readable
 * relative time.
 *
 * Examples:
 *
 *     Just now
 *     2 minutes ago
 *     3 hours ago
 *     4 days ago
 *     08/10/2026
 */
function formatRelativeTime(
    timestamp
) {

    const date =
        new Date(timestamp);


    const now =
        new Date();


    const diffMs =
        now - date;


    const diffSeconds =
        Math.floor(
            diffMs / 1000
        );


    if (diffSeconds < 60) {

        return "Just now";
    }


    const diffMinutes =
        Math.floor(
            diffSeconds / 60
        );


    if (diffMinutes < 60) {

        return `${
            diffMinutes
        } minute${
            diffMinutes === 1
                ? ""
                : "s"
        } ago`;
    }


    const diffHours =
        Math.floor(
            diffMinutes / 60
        );


    if (diffHours < 24) {

        return `${
            diffHours
        } hour${
            diffHours === 1
                ? ""
                : "s"
        } ago`;
    }


    const diffDays =
        Math.floor(
            diffHours / 24
        );


    if (diffDays < 7) {

        return `${
            diffDays
        } day${
            diffDays === 1
                ? ""
                : "s"
        } ago`;
    }


    return date.toLocaleDateString();
}


/*
 * Refresh only the visual representation of Last Active
 * timestamps.
 *
 * This does NOT contact the backend.
 *
 * The actual last_active value comes from the server.
 * We simply recalculate how old that timestamp is.
 */
function refreshRelativeTimes() {

    const elements =
        document.querySelectorAll(
            "[data-last-active]"
        );


    elements.forEach(
        element => {

            const timestamp =
                element.dataset.lastActive;


            element.innerText =
                formatRelativeTime(
                    timestamp
                );
        }
    );
}


/*
 * Update relative timestamps every 30 seconds while
 * the page is open.
 *
 * This is intentionally a local UI operation rather
 * than a repeated API request.
 */
setInterval(
    refreshRelativeTimes,
    30000
);


/* =========================================================
   SESSION LOGOUT - SPECIFIC DEVICE
   ========================================================= */

/*
 * Perform the actual API request to revoke one session.
 *
 * This function does NOT ask for confirmation.
 *
 * Confirmation is handled by logoutSession().
 */
async function performLogoutSession(
    sessionId
) {

    let token =
        getAccessToken();


    let res = await fetch(
        `/sessions/${sessionId}`,
        {
            method: "DELETE",

            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    /* ---------------------------------------------
       Access-token refresh
       --------------------------------------------- */

    if (res.status === 401) {

        const refreshed =
            await refreshAccessToken();


        if (!refreshed) {

            logout();

            return;
        }


        token =
            getAccessToken();


        res = await fetch(
            `/sessions/${sessionId}`,
            {
                method: "DELETE",

                headers: {
                    "Authorization":
                        `Bearer ${token}`
                }
            }
        );
    }


    /* ---------------------------------------------
       Error state
       --------------------------------------------- */

    if (!res.ok) {

        const data =
            await res.json();


        alert(
            data.detail ||
            "Unable to logout session."
        );


        return;
    }


    alert(
        "Session logged out successfully."
    );


    /*
     * Reload the dashboard from the backend instead
     * of manually manipulating the session count/cards.
     *
     * This keeps the frontend synchronized with the
     * authoritative server state.
     */
    await loadSessionDashboard();
}


/*
 * User-facing entry point for logging out a specific
 * device.
 *
 * This function only handles confirmation.
 * The actual API operation is delegated to
 * performLogoutSession().
 */
function logoutSession(
    sessionId
) {

    showConfirmationModal(

        "Logout this device?",

        "This will sign out this device and revoke its session.",

        "Logout Device",

        () =>
            performLogoutSession(
                sessionId
            )
    );
}


/* =========================================================
   SESSION LOGOUT - ALL DEVICES
   ========================================================= */

/*
 * Perform the actual API request to revoke all sessions.
 *
 * This function does NOT ask for confirmation.
 */
async function performLogoutAllDevices() {

    let token =
        getAccessToken();


    let res = await fetch(
        "/sessions/logout-all",
        {
            method: "POST",

            headers: {
                "Authorization":
                    `Bearer ${token}`
            }
        }
    );


    /* ---------------------------------------------
       Access-token refresh
       --------------------------------------------- */

    if (res.status === 401) {

        const refreshed =
            await refreshAccessToken();


        if (!refreshed) {

            logout();

            return;
        }


        token =
            getAccessToken();


        res = await fetch(
            "/sessions/logout-all",
            {
                method: "POST",

                headers: {
                    "Authorization":
                        `Bearer ${token}`
                }
            }
        );
    }


    /* ---------------------------------------------
       Error state
       --------------------------------------------- */

    if (!res.ok) {

        const data =
            await res.json();


        alert(
            data.detail ||
            "Unable to logout from all devices."
        );


        return;
    }


    const data =
        await res.json();


    alert(
        data.message
    );


    /*
     * The current session was also revoked, so this
     * browser can no longer remain authenticated.
     */
    localStorage.clear();


    window.location.href =
        "/";
}


/*
 * User-facing entry point for logging out all devices.
 *
 * This action is more destructive than logging out
 * a single device, so it receives its own confirmation.
 */
function logoutAllDevices() {

    showConfirmationModal(

        "Logout all devices?",

        "This will sign out all active devices, including this device. You will need to log in again.",

        "Logout All",

        performLogoutAllDevices
    );
}


/* =========================================================
   CONFIRMATION MODAL
   ========================================================= */

/*
 * Display the reusable confirmation modal.
 *
 * The modal receives:
 *
 *     title       → modal heading
 *     message     → explanation
 *     actionText  → confirmation button label
 *     action      → function to execute after confirmation
 */
function showConfirmationModal(
    title,
    message,
    actionText,
    action
) {

    document.getElementById(
        "confirmation-title"
    ).innerText =
        title;


    document.getElementById(
        "confirmation-message"
    ).innerText =
        message;


    document.getElementById(
        "confirmation-action-button"
    ).innerText =
        actionText;


    /*
     * Store the requested operation until the user
     * explicitly confirms it.
     */
    pendingConfirmationAction =
        action;


    document.getElementById(
        "confirmation-modal"
    ).style.display =
        "flex";
}


/*
 * Close the confirmation modal and discard any pending
 * destructive action.
 */
function closeConfirmationModal() {

    document.getElementById(
        "confirmation-modal"
    ).style.display =
        "none";


    pendingConfirmationAction =
        null;
}


/*
 * Execute the action currently waiting for confirmation.
 *
 * This is deliberately the only place that consumes
 * pendingConfirmationAction.
 */
async function confirmPendingAction() {

    if (!pendingConfirmationAction) {
        return;
    }


    const action =
        pendingConfirmationAction;


    /*
     * Clear the pending action before executing it.
     *
     * This prevents accidental repeated execution if
     * the modal is interacted with again.
     */
    closeConfirmationModal();


    await action();
}
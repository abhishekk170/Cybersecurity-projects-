/* =====================================
   NOVABANK - DEMO BANKING WEBSITE
   Now wired to the Flask backend (was: localStorage/sessionStorage demo)
===================================== */


/* =========================
   CONFIG
========================= */

// Change this if your backend runs somewhere else.
const API_BASE_URL = "http://127.0.0.1:5000";


/* =========================
   ELEMENTS
========================= */

const authPage = document.getElementById("authPage");

const bankApp = document.getElementById("bankApp");

const loginFormContainer =
    document.getElementById("loginFormContainer");

const registerFormContainer =
    document.getElementById("registerFormContainer");

const loginForm =
    document.getElementById("loginForm");

const registerForm =
    document.getElementById("registerForm");

const showRegister =
    document.getElementById("showRegister");

const showLogin =
    document.getElementById("showLogin");

const logoutBtn =
    document.getElementById("logoutBtn");

const welcomeText =
    document.getElementById("welcomeText");

const userAvatar =
    document.getElementById("userAvatar");

const accountBalance =
    document.getElementById("accountBalance");

const transactionsList =
    document.getElementById("transactionsList");

const toast =
    document.getElementById("toast");

const toastTitle =
    document.getElementById("toastTitle");

const toastMessage =
    document.getElementById("toastMessage");


/* =========================
   API HELPER
========================= */

async function api(path, options = {}) {

    let response;

    try {

        response = await fetch(API_BASE_URL + path, {

            credentials: "include", // send/receive the HttpOnly session cookie

            headers: {
                "Content-Type": "application/json",
                ...(options.headers || {})
            },

            ...options

        });

    } catch (networkErr) {

        // fetch() itself failed: backend down, wrong port, CORS block, etc.set
        console.error("Network/CORS error calling", path, networkErr);

        throw new Error(
            "Could not reach the server. Is the backend running at " +
            API_BASE_URL + "?"
        );
    }

    let data = null;

    try {
        data = await response.json();
    } catch (e) {
        data = null;
    }

    if (!response.ok) {

        const message =
            (data && data.error) ||
            "Something went wrong. Please try again.";

        console.error("API error on", path, response.status, data);

        throw new Error(message);
    }

    return data;
}


/* =========================
   SWITCH LOGIN / REGISTER
========================= */

showRegister.addEventListener("click", function () {

    loginFormContainer.classList.add("hidden");

    registerFormContainer.classList.remove("hidden");

});


showLogin.addEventListener("click", function () {

    registerFormContainer.classList.add("hidden");

    loginFormContainer.classList.remove("hidden");

});


/* =========================
   REGISTER
========================= */

registerForm.addEventListener("submit", async function (event) {

    event.preventDefault();


    const name =
        document.getElementById("registerName").value.trim();

    const username =
        document.getElementById("registerUsername").value.trim();

    const password =
        document.getElementById("registerPassword").value;

    const confirmPassword =
        document.getElementById("confirmPassword").value;


    /* Check passwords */

    if (password !== confirmPassword) {

        showToast(
            "Registration failed",
            "Passwords do not match."
        );

        return;
    }


    /* Basic validation */

    if (
        name === "" ||
        username === "" ||
        password === ""
    ) {

        showToast(
            "Registration failed",
            "Please fill all fields."
        );

        return;
    }


    try {

        await api("/api/auth/register", {
            method: "POST",
            body: JSON.stringify({ name, username, password })
        });

        showToast(
            "Account created",
            "Your demo account was created successfully."
        );

        /* Clear registration */

        registerForm.reset();

        /* Go back to login */

        setTimeout(function () {

            registerFormContainer.classList.add("hidden");

            loginFormContainer.classList.remove("hidden");

            document.getElementById("loginUsername").value =
                username;

        }, 900);

    } catch (err) {

        showToast(
            "Registration failed",
            err.message
        );
    }

});


/* =========================
   LOGIN
========================= */

loginForm.addEventListener("submit", async function (event) {

    event.preventDefault();


    const username =
        document.getElementById("loginUsername").value.trim();

    const password =
        document.getElementById("loginPassword").value;


    try {

        const data = await api("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({ username, password })
        });

        // Guard against an unexpected response shape from the backend,
        // instead of silently throwing inside data.user.name below.
        if (!data || !data.user || !data.user.name) {

            console.error(
                "Unexpected /api/auth/login response shape:",
                data
            );

            throw new Error(
                "Login response was missing user data. " +
                "Check the backend response shape in the console."
            );
        }

        showToast(
            "Login successful",
            "Your banking session is now active."
        );

        await openBankingDashboard(data.user.name);

    } catch (err) {

        showToast(
            "Login failed",
            err.message
        );
    }

});


/* =========================
   OPEN DASHBOARD
========================= */

async function openBankingDashboard(name) {

    authPage.classList.add("hidden");

    bankApp.classList.remove("hidden");


    /* User's first letter */

    userAvatar.textContent =
        name.charAt(0).toUpperCase();


    /* Greeting */

    const hour =
        new Date().getHours();


    let greeting;


    if (hour < 12) {

        greeting = "Good morning";

    } else if (hour < 18) {

        greeting = "Good afternoon";

    } else {

        greeting = "Good evening";

    }


    welcomeText.textContent =
        `${greeting}, ${name.split(" ")[0]}`;


    await loadAccount();

    await loadTransactions();

}


/* =========================
   LOAD ACCOUNT (balance)
========================= */

async function loadAccount() {

    try {

        const data = await api("/api/account");

        accountBalance.textContent =
            formatCurrency(data.balance);

    } catch (err) {

        // If the session died server-side, bounce back to login.
        if (err.message.toLowerCase().includes("auth") ||
            err.message.toLowerCase().includes("session")) {

            returnToLogin();
        }
    }

}


/* =========================
   LOAD TRANSACTIONS
========================= */

async function loadTransactions() {

    try {

        const data = await api("/api/transactions?limit=10");

        renderTransactions(data.transactions);

    } catch (err) {

        transactionsList.innerHTML =
            `<p style="padding:16px;">Could not load transactions.</p>`;
    }

}


function renderTransactions(transactions) {

    transactionsList.innerHTML = "";

    if (!transactions || transactions.length === 0) {

        transactionsList.innerHTML =
            `<p style="padding:16px;">No transactions yet.</p>`;

        return;
    }

    transactions.forEach(function (tx) {

        const row = document.createElement("div");
        row.className = "transaction";

        const icon = document.createElement("div");
        icon.className = "transaction-icon";
        icon.textContent = (tx.category || tx.description || "?")
            .charAt(0)
            .toUpperCase();

        const details = document.createElement("div");
        details.className = "transaction-details";

        const title = document.createElement("strong");
        title.textContent = tx.description;

        const meta = document.createElement("span");
        meta.textContent =
            `${tx.category} • ${formatDate(tx.created_at)}`;

        details.appendChild(title);
        details.appendChild(meta);

        const amount = document.createElement("strong");
        amount.className =
            "amount " + (tx.type === "credit" ? "credit" : "debit");
        amount.textContent =
            (tx.type === "credit" ? "+ " : "- ") +
            formatCurrency(tx.amount);

        row.appendChild(icon);
        row.appendChild(details);
        row.appendChild(amount);

        transactionsList.appendChild(row);

    });

}


function formatCurrency(amount) {

    const num = Number(amount) || 0;

    return "₹ " + num.toLocaleString("en-IN", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    });

}


function formatDate(isoString) {

    if (!isoString) return "";

    try {

        const d = new Date(isoString.replace(" ", "T") + "Z");

        return d.toLocaleDateString("en-IN", {
            day: "numeric",
            month: "short"
        });

    } catch (e) {

        return isoString;
    }

}


/* =========================
   LOGOUT
========================= */

logoutBtn.addEventListener("click", async function () {

    try {

        await api("/api/auth/logout", { method: "POST" });

    } catch (err) {

        // Even if the request fails, still clear the local UI state.
    }

    returnToLogin();

    showToast(
        "Logged out",
        "Your banking session has ended."
    );

});


function returnToLogin() {

    /* Return to login */

    bankApp.classList.add("hidden");

    authPage.classList.remove("hidden");


    /* Clear password */

    document.getElementById(
        "loginPassword"
    ).value = "";

}


/* =========================
   CHECK ACTIVE SESSION
========================= */

window.addEventListener("load", async function () {

    try {

        const data = await api("/api/auth/session");

        if (data.authenticated) {

            await openBankingDashboard(data.user.name);
        }

    } catch (err) {

        // No valid session - stay on the login page.
    }

});


/* =========================
   TOAST
========================= */

function showToast(title, message) {

    toastTitle.textContent = title;

    toastMessage.textContent = message;

    toast.classList.add("show");


    setTimeout(function () {

        toast.classList.remove("show");

    }, 3000);

}
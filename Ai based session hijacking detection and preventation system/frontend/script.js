/* =====================================
   NOVABANK - DEMO BANKING WEBSITE
   Wired to the Flask backend.
   Adds: working sidebar navigation and
   Transfers / Transactions / Settings pages.
   Existing login/register/logout/session/
   account/transaction logic is unchanged.
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

// Navigation / pages
const navLinks =
    document.querySelectorAll(".nav-link");

const pageViews =
    document.querySelectorAll(".page-view");

const quickGoButtons =
    document.querySelectorAll("[data-goto]");

// Transfers page
const transferForm =
    document.getElementById("transferForm");

const transferConfirm =
    document.getElementById("transferConfirm");

const recentTransfersList =
    document.getElementById("recentTransfersList");

// Transactions page
const fullTransactionsList =
    document.getElementById("fullTransactionsList");

const transactionFilters =
    document.getElementById("transactionFilters");

// Settings page
const settingsUsername =
    document.getElementById("settingsUsername");

const settingsAccountNumber =
    document.getElementById("settingsAccountNumber");

const passwordForm =
    document.getElementById("passwordForm");

const passwordConfirm =
    document.getElementById("passwordConfirm");

const preferencesForm =
    document.getElementById("preferencesForm");

const preferencesConfirm =
    document.getElementById("preferencesConfirm");


/* =========================
   IN-MEMORY DEMO STATE
========================= */

// Current signed-in user's display name, used for greetings/avatar
// and as a stand-in "account owner" on the Settings page.
let currentUserName = "";
let currentUsername = "";

// Full transaction list for the Transactions page (fetched once per
// session and re-rendered locally when the filter tabs are used).
let allTransactions = [];
let currentTransactionFilter = "all";

// Demo-only transfers. Not sent anywhere: this project's backend does
// not have a transfers endpoint yet (see TODO near submitTransfer()).
let demoTransfers = [];


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

        currentUsername = data.user.username || username;

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


    currentUserName = name;


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


    // Reset in-memory, per-session demo state and always land on
    // Overview after a fresh login.
    demoTransfers = [];
    allTransactions = [];
    currentTransactionFilter = "all";
    switchPage("overview");


    await loadAccount();

    await loadTransactions();

    populateSettingsProfile();

}


/* =========================
   LOAD ACCOUNT (balance)
========================= */

async function loadAccount() {

    try {

        const data = await api("/api/account");

        accountBalance.textContent =
            formatCurrency(data.balance);

        // Used by the Settings > Profile section further down.
        if (data.account_number) {

            settingsAccountNumber.value = data.account_number;

        } else {

            settingsAccountNumber.value = "—";
        }

    } catch (err) {

        // If the session died server-side, bounce back to login.
        if (err.message.toLowerCase().includes("auth") ||
            err.message.toLowerCase().includes("session")) {

            returnToLogin();
        }
    }

}


/* =========================
   LOAD TRANSACTIONS (Overview - recent only)
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

        transactionsList.appendChild(buildTransactionRow(tx));

    });

}


/* =========================
   LOAD TRANSACTIONS (Transactions page - full history)
========================= */

async function loadFullTransactions() {

    fullTransactionsList.innerHTML =
        `<p style="padding:16px;">Loading transactions…</p>`;

    try {

        // No "limit" query param = full history for this demo account.
        // TODO (backend): if the account ever has a very large number
        // of transactions, switch this to real pagination instead of
        // fetching everything at once.
        const data = await api("/api/transactions");

        allTransactions = data.transactions || [];

        renderFullTransactions();

    } catch (err) {

        fullTransactionsList.innerHTML =
            `<p style="padding:16px;">Could not load transactions.</p>`;
    }

}


function renderFullTransactions() {

    fullTransactionsList.innerHTML = "";

    const filtered = allTransactions.filter(function (tx) {

        if (currentTransactionFilter === "all") {
            return true;
        }

        return tx.type === currentTransactionFilter;

    });

    if (filtered.length === 0) {

        fullTransactionsList.innerHTML =
            `<p style="padding:16px;">No transactions to show.</p>`;

        return;
    }

    filtered.forEach(function (tx) {

        fullTransactionsList.appendChild(buildTransactionRow(tx));

    });

}


// Shared row-builder used by both the Overview "recent" list and the
// full Transactions page, so both stay visually identical.
function buildTransactionRow(tx) {

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

    return row;

}


if (transactionFilters) {

    transactionFilters.addEventListener("click", function (event) {

        const tab = event.target.closest(".filter-tab");

        if (!tab) {
            return;
        }

        transactionFilters
            .querySelectorAll(".filter-tab")
            .forEach(function (t) {
                t.classList.remove("active");
            });

        tab.classList.add("active");

        currentTransactionFilter = tab.dataset.filter;

        renderFullTransactions();

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
   SIDEBAR NAVIGATION
========================= */

// Maps a page name (from data-page / data-goto) to a friendly
// topbar label, so the header still makes sense on every page.
const PAGE_LABELS = {
    overview: "PERSONAL BANKING",
    transfers: "MOVE MONEY",
    transactions: "ACCOUNT ACTIVITY",
    settings: "ACCOUNT SETTINGS"
};

const topbarLabel =
    document.getElementById("topbarLabel");

function switchPage(pageName) {

    // Toggle the page-view sections.
    pageViews.forEach(function (view) {

        if (view.id === pageName + "Page") {

            view.classList.remove("hidden");

        } else {

            view.classList.add("hidden");
        }

    });

    // Toggle the sidebar's active state.
    navLinks.forEach(function (link) {

        link.classList.toggle(
            "active",
            link.dataset.page === pageName
        );

    });

    if (topbarLabel && PAGE_LABELS[pageName]) {

        topbarLabel.textContent = PAGE_LABELS[pageName];
    }

    // Lazy-load data only the first time a page is opened, so we
    // don't hit the backend more than necessary.
    if (pageName === "transactions" && allTransactions.length === 0) {

        loadFullTransactions();
    }

}


navLinks.forEach(function (link) {

    link.addEventListener("click", function () {

        switchPage(link.dataset.page);

    });

});


// "Send Money" / "View all" style shortcuts on the Overview page.
quickGoButtons.forEach(function (button) {

    button.addEventListener("click", function () {

        switchPage(button.dataset.goto);

    });

});


/* =========================
   TRANSFERS (demo only)
========================= */

if (transferForm) {

    transferForm.addEventListener("submit", function (event) {

        event.preventDefault();

        const recipient =
            document.getElementById("transferRecipient").value.trim();

        const amount =
            parseFloat(document.getElementById("transferAmount").value);

        const note =
            document.getElementById("transferNote").value.trim();

        if (!recipient || !amount || amount <= 0) {

            showToast(
                "Transfer failed",
                "Please enter a recipient and a valid amount."
            );

            return;
        }

        // TODO (backend): this is a demo-only transfer. Once the Flask
        // backend exposes something like POST /api/transfers, replace
        // this block with a real api("/api/transfers", { method: "POST",
        // body: JSON.stringify({ recipient, amount, note }) }) call, and
        // refresh the balance/transactions afterwards.
        submitDemoTransfer(recipient, amount, note);

    });

}


function submitDemoTransfer(recipient, amount, note) {

    const transfer = {
        recipient: recipient,
        amount: amount,
        note: note,
        created_at: new Date().toISOString()
    };

    demoTransfers.unshift(transfer);

    renderRecentTransfers();

    transferForm.reset();

    transferConfirm.classList.remove("hidden");

    setTimeout(function () {

        transferConfirm.classList.add("hidden");

    }, 3000);

    showToast(
        "Transfer submitted",
        `₹${amount.toFixed(2)} sent to ${recipient} (demo only).`
    );

}


function renderRecentTransfers() {

    if (demoTransfers.length === 0) {

        recentTransfersList.innerHTML =
            `<p style="padding:16px;">No transfers yet this session.</p>`;

        return;
    }

    recentTransfersList.innerHTML = "";

    demoTransfers.forEach(function (t) {

        const row = document.createElement("div");
        row.className = "transaction";

        const icon = document.createElement("div");
        icon.className = "transaction-icon";
        icon.textContent = t.recipient.charAt(0).toUpperCase();

        const details = document.createElement("div");
        details.className = "transaction-details"; 

        const title = document.createElement("strong");
        title.textContent = t.recipient;

        const meta = document.createElement("span");
        meta.textContent =
            (t.note ? t.note + " • " : "") + formatDate(t.created_at);

        details.appendChild(title);
        details.appendChild(meta);

        const amount = document.createElement("strong");
        amount.className = "amount debit";
        amount.textContent = "- " + formatCurrency(t.amount);

        row.appendChild(icon);
        row.appendChild(details);
        row.appendChild(amount);

        recentTransfersList.appendChild(row);

    });

}


/* =========================
   SETTINGS (demo only)
========================= */

function populateSettingsProfile() {

    if (settingsUsername) {

        settingsUsername.value = currentUsername || currentUserName || "";
    }

}


if (passwordForm) {

    passwordForm.addEventListener("submit", function (event) {

        event.preventDefault();

        const current =
            document.getElementById("currentPassword").value;

        const next =
            document.getElementById("newPassword").value;

        const confirm =
            document.getElementById("confirmNewPassword").value;

        if (!current || !next || !confirm) {

            showToast(
                "Update failed",
                "Please fill all password fields."
            );

            return;
        }

        if (next !== confirm) {

            showToast(
                "Update failed",
                "New passwords do not match."
            );

            return;
        }

        // TODO (backend): wire this to a real endpoint, e.g.
        // POST /api/auth/change-password, once it exists. For now this
        // never touches the real account and only updates the UI.
        passwordForm.reset();

        passwordConfirm.classList.remove("hidden");

        setTimeout(function () {

            passwordConfirm.classList.add("hidden");

        }, 3000);

        showToast(
            "Password updated",
            "Your password change was recorded (demo only)."
        );

    });

}


if (preferencesForm) {

    preferencesForm.addEventListener("submit", function (event) {

        event.preventDefault();

        // TODO (backend): persist these to something like
        // PUT /api/account/preferences once that endpoint exists.
        // Currently kept in memory only, for the length of the session.
        preferencesConfirm.classList.remove("hidden");

        setTimeout(function () {

            preferencesConfirm.classList.add("hidden");

        }, 3000);

        showToast(
            "Preferences saved",
            "Your notification preferences were updated (demo only)."
        );

    });

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

            currentUsername = data.user.username || "";

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

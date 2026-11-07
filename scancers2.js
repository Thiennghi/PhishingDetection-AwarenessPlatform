let csrfReady;
async function fetchCsrfToken() {
    const response = await fetch('csrf.php', { headers: { Accept: 'application/json' } });
    const data = await response.json();
    if (!response.ok || !data.token) throw new Error('Server session unavailable. Reload the page.');
    SecurityConfig.MAX_MESSAGE_LENGTH = data.max_input_length;
    SecurityConfig.MAX_REPORT_LENGTH = data.max_report_length || SecurityConfig.MAX_REPORT_LENGTH;
    return data.token;
}
async function postToServer(endpoint, body) {
    const send = token => fetch(endpoint, {
        method: 'POST', credentials: 'same-origin',
        headers: { Accept: 'application/json', 'X-CSRF-Token': token }, body
    });
    let response = await send(await csrfReady);
    if (response.status === 403) {
        csrfReady = fetchCsrfToken();
        response = await send(await csrfReady);
    }
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.message || 'Request failed.');
    return data;
}
document.addEventListener("DOMContentLoaded", function () {
    csrfReady = fetchCsrfToken();
    csrfReady.catch(() => {});
    const navButtons = document.querySelectorAll(".nav-item");
    const form = document.getElementById("detectionForm");
    const clearBtn = document.getElementById("clearBtn");
    const reportForm = document.getElementById("reportForm");

    navButtons.forEach(button => {
        button.addEventListener("click", () => {
            const tabTarget = button.getAttribute("data-tab");
            switchTab(tabTarget);
        });
    });

    // Replaces the inline onclick="" attributes that used to be in index.html,
    // so the Content-Security-Policy does not need 'unsafe-inline' for scripts.
    document.addEventListener("click", function (e) {
        const el = e.target.closest("[data-action]");
        if (!el) return;

        switch (el.dataset.action) {
            case "switch-tab":
                switchTab(el.dataset.tabTarget);
                break;
            case "load-sample":
                loadSample(el.dataset.sample);
                break;
            case "reset-all":
                resetAll();
                break;
            case "toggle-history":
                toggleScanHistory();
                break;
            case "close-history":
                closeScanHistory();
                break;
        }
    });

    if (form) {
        form.addEventListener("submit", function (e) {
            e.preventDefault();
            runAnalysis();
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", function () {
            const messageInput = document.getElementById("messageInput");
            const resultCard = document.getElementById("resultCard");

            analysisGeneration++;
            if (messageInput) messageInput.value = "";
            if (resultCard) resultCard.classList.add("hidden");
            clearValidationErrors();


        });
    }

    if (reportForm) {
        reportForm.addEventListener("submit", function (e) {
            e.preventDefault();
            handleReport(e);
        });
    }

    loadAwarenessTable();
});

function switchTab(tabId) {
    if (!tabId) return;

    document.querySelectorAll(".tab-content").forEach(tab => tab.classList.remove("active"));
    document.querySelectorAll(".nav-item").forEach(btn => btn.classList.remove("active"));

    const targetTab = document.getElementById(tabId);
    const targetBtn = document.querySelector(`[data-tab="${tabId}"]`);

    if (targetTab) targetTab.classList.add("active");
    if (targetBtn) targetBtn.classList.add("active");

    if (tabId === "awareness") {
        loadAwarenessTable();
    }
}

function loadAwarenessTable() {
    if (window.renderAwareness) window.renderAwareness();
}

const sampleData = {
    url_phishing: "https://paypal.com.attacker.test/login",
    url_download: "https://files.example.test/invoice.pdf.exe",
    scam_task: "Complete product boosting tasks for commission. Deposit USDT to unlock your earnings.",
    scam_bec: "Please wire payment to our new bank account immediately. Keep this confidential and do not call.",
    scam_captcha: "To verify you're human, press Windows + R then Ctrl + V to run the verification command.",
    phishing_netflix:
        "Your Netflix account has been suspended due to payment failure. Please click the link immediately to verify billing and avoid permanent account termination: http://bit.ly/fake-netflix-link",
    phishing_bank:
        "CHASE ALERT: Urgent activity detected. Your card is restricted. Confirm identity now at http://chase-security-update.com or call immediately.",
    scam_lottery:
        "CONGRATULATIONS! You have won $1,500,000 in the International Email Lottery! Reply with your bank info and deposit $250 fee to process funds.",
    legit_email:
        "Hi team, attached are the meeting notes and project milestones for next week's sprint. Let me know if you have any questions."
};

function loadSample(key) {
    if (!sampleData[key]) return;
    const messageInput = document.getElementById("messageInput");
    if (!messageInput) return;
    messageInput.value = sampleData[key];
    const mode = document.getElementById('scanMode');
    if (mode) mode.value = key.startsWith('url_') ? 'url' : 'message';
    clearValidationErrors();
}

let scanStats = { total: 0, highRisk: 0, legit: 0 };
let analysisGeneration = 0;

function runAnalysis() {
    const messageInput = document.getElementById("messageInput");
    if (!messageInput) {
        console.error("messageInput element was not found.");
        return;
    }

    const input = messageInput.value;
    const scanMode = document.getElementById('scanMode')?.value === 'url' ? 'url' : 'message';
    const validation = validateAndSanitizeInput(input, "message");

    if (!validation.isValid) {
        displayValidationErrors(validation.errors);
        logSecurityEvent("VALIDATION_FAILED", { errors: validation.errors });
        return;
    }

    if (scanMode === 'url') {
        const tokens = window.DetectionEngine.normalize(validation.sanitized).split(/\s+/);
        if (tokens.length > 20 || tokens.some(token => !/^(?:https?:\/\/|www\.|(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:[/:?#]|$))/i.test(token) || window.DetectionEngine.urlsFrom(token).length !== 1)) {
            displayValidationErrors(['Enter up to 20 HTTP(S) URLs, one per line, without additional message text.']);
            return;
        }
    }
    clearValidationErrors();

    if (!checkRateLimit()) {
        displayValidationErrors(["Too many requests. Please wait before submitting again."]);
        logSecurityEvent("RATE_LIMIT_EXCEEDED", { timestamp: Date.now() });
        return;
    }

    const localResult = window.DetectionEngine.evaluate(validation.sanitized, window.PhishingDataset, [], scanMode);
    const generation = ++analysisGeneration;

    const formData = new FormData();
    formData.append("user_input", validation.sanitized);
    formData.append("scan_mode", scanMode);

    postToServer('scan.php', formData)
    .then(data => {
        if (generation !== analysisGeneration) return;
        renderDetectionResult(data);
        updateDashboardStats(data.risk_score);
        loadAwarenessTable();
    })
    .catch(error => {
        if (generation !== analysisGeneration) return;
        renderDetectionResult(localResult);
        updateDashboardStats(localResult.risk_score);
        displayValidationErrors([error.message, "Showing a local estimate; this scan was not saved."]);
    });
}

function renderDetectionResult(data) {
    renderUrlResults(data.urls || []);
    const signals = data.signals || { phishing: 0, scam: 0, malware: 0 };
    renderResults(data.risk_score, signals.phishing, signals.scam, signals.malware, data.flags || [], data.classification);
    const detail = document.getElementById('detectorDetails');
    if (detail) {
        detail.textContent = `Rules: ${data.detector_version || 'unknown'}. ` +
            (data.reputation_checked && data.active_reputation_entries > 0
                ? 'Local phishing-feed records checked. '
                : 'No active phishing-feed protection in this result. ') +
            (data.community_checked ? 'Reviewed community reports checked. ' : '') +
            'Text and visible URLs only; a low score does not prove safety.';
    }
    const sources = document.getElementById('detectorSources');
    if (sources) {
        sources.replaceChildren();
        const ids = new Set((data.evidence || []).flatMap(item => item.sources));
        window.PhishingDataset.sources.filter(source => ids.has(source.id)).forEach(source => {
            const link = document.createElement('a');
            link.textContent = `${source.publisher}: ${source.title}`;
            link.href = source.url;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            const item = document.createElement('li');
            item.appendChild(link);
            sources.appendChild(item);
        });
    }
}

function renderUrlResults(links) {
    const section = document.getElementById('urlResults');
    const list = document.getElementById('urlResultsList');
    if (!section || !list) return;
    list.replaceChildren();
    if (!links.length) { section.classList.add('hidden'); return; }
    section.classList.remove('hidden');
    links.forEach((link, index) => {
        const card = document.createElement('article');
        card.className = 'url-check';
        const title = document.createElement('h5');
        title.textContent = `Link ${index + 1}: ${link.verdict} — ${link.risk_score}/100`;
        const address = document.createElement('code');
        address.className = 'url-address';
        address.textContent = String(link.url).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
        const host = document.createElement('p');
        host.textContent = `Hostname: ${link.hostname}. Assessment: ${link.threat_type}.`;
        const status = document.createElement('p');
        status.textContent = `Reputation: ${link.reputation_status}. ` +
            (link.recognized_domain ? 'Hostname is in a reference brand list; page safety is not verified.' : 'Website content has not been inspected.');
        const reasons = document.createElement('ul');
        const labels = (link.reasons || []).map(reason => reason.label);
        if (!labels.length) labels.push('No configured URL warning matched. This is not a safe-link certification.');
        labels.forEach(label => { const item = document.createElement('li'); item.textContent = label; reasons.appendChild(item); });
        card.append(title, address, host, status, reasons);
        if (link.embedded_destination) {
            const target = document.createElement('p');
            target.textContent = `Embedded destination hostname: ${link.embedded_destination} (not visited).`;
            card.appendChild(target);
        }
        const reportButton = document.createElement('button');
        reportButton.type = 'button'; reportButton.className = 'btn-secondary';
        reportButton.textContent = 'Report this link →';
        reportButton.addEventListener('click', () => prepareReport(link.url, '', /scam/i.test(link.threat_type) ? 'scam' : /download/i.test(link.threat_type) ? 'malware' : 'phishing'));
        card.appendChild(reportButton);
        list.appendChild(card);
    });
}

function renderResults(score, pPhish, pScam, pLegit, flags, classification) {
    const resultCard = document.getElementById("resultCard");
    const riskCircle = document.getElementById("scoreCircle");
    const scoreText = document.getElementById("riskScore");
    const label = document.getElementById("classificationLabel");
    const desc = document.getElementById("classificationDesc");
    const flagBox = document.getElementById("flagContainer");

    if (!resultCard || !riskCircle || !scoreText || !label || !desc || !flagBox) {
        console.error("One or more result elements are missing from the HTML.");
        return;
    }

    resultCard.classList.remove("hidden");
    scoreText.textContent = score;

    const phishingBar = document.getElementById("phishingBar");
    const phishingProb = document.getElementById("phishingProb");
    if (phishingBar) phishingBar.style.width = pPhish + "%";
    if (phishingProb) phishingProb.textContent = pPhish + "/100";

    const scamBar = document.getElementById("scamBar");
    const scamProb = document.getElementById("scamProb");
    if (scamBar) scamBar.style.width = pScam + "%";
    if (scamProb) scamProb.textContent = pScam + "/100";

    const legitBar = document.getElementById("legitBar");
    const legitProb = document.getElementById("legitProb");
    if (legitBar) legitBar.style.width = pLegit + "%";
    if (legitProb) legitProb.textContent = pLegit + "/100";

    if (score >= 60) {
        riskCircle.style.borderColor = "var(--danger)";
        label.textContent = "HIGH RISK DETECTED";
        label.style.color = "var(--danger)";
        desc.textContent = "This message demonstrates prominent indicators of phishing or scam activity.";
    } else if (score >= 30) {
        riskCircle.style.borderColor = "var(--warning)";
        label.textContent = "SUSPICIOUS CONTENT";
        label.style.color = "var(--warning)";
        desc.textContent = "Exercise caution. Contains suspicious patterns or ambiguous links.";
    } else {
        riskCircle.style.borderColor = "var(--safe)";
        label.textContent = "LOW RISK — NOT VERIFIED";
        label.style.color = "var(--safe)";
        desc.textContent = "Few configured indicators matched. Verify the sender and destination independently.";
    }

    if (classification) label.textContent = classification === "SAFE" ? "LOW RISK — NOT VERIFIED" : classification;

    flagBox.innerHTML = "";
    if (!flags || flags.length === 0) {
        flagBox.innerHTML = '<span class="badge">No overt threat markers found</span>';
    } else {
        flags.forEach(flag => {
            const badge = document.createElement("span");
            badge.className = score >= 60 ? "badge danger" : "badge warning";
            badge.textContent = flag;
            flagBox.appendChild(badge);
        });
    }

    resultCard.scrollIntoView({ behavior: "smooth" });
}

function updateDashboardStats(riskScore) {
    scanStats.total++;

    if (riskScore >= 60) {
        scanStats.highRisk++;
    } else if (riskScore < 30) {
        scanStats.legit++;
    }

    const statTotalScans = document.getElementById("statTotalScans");
    const statHighRisk = document.getElementById("statHighRisk");
    const statLegit = document.getElementById("statLegit");

    if (statTotalScans) statTotalScans.textContent = scanStats.total;
    if (statHighRisk) statHighRisk.textContent = scanStats.highRisk;
    if (statLegit) statLegit.textContent = scanStats.legit;
}

async function handleReport(e) {
    e.preventDefault();

    const threatContentElement = document.getElementById("threatContent");
    const threatTypeElement = document.getElementById("threatType");
    if (!threatContentElement || !threatTypeElement) {
        console.error("Report form elements are missing.");
        return;
    }

    const url = document.getElementById('reportUrl')?.value.trim() || '';
    if (url && !/^https?:\/\/\S+$/i.test(url)) {
        displayValidationErrors(['Enter a complete HTTP(S) URL without spaces.'], 'reportForm'); return;
    }
    const threatContent = threatContentElement.value || (url ? 'Suspicious URL submitted for review.' : '');
    const threatType = threatTypeElement.value;
    const validation = validateAndSanitizeInput(threatContent, "report");

    if (!validation.isValid) {
        displayValidationErrors(validation.errors, 'reportForm');
        logSecurityEvent("REPORT_VALIDATION_FAILED", { errors: validation.errors });
        return;
    }

    if (!checkRateLimit()) {
        displayValidationErrors(["Too many reports. Please wait before submitting again."], "reportForm");
        logSecurityEvent("REPORT_RATE_LIMIT_EXCEEDED", { timestamp: Date.now() });
        return;
    }

    clearValidationErrors();
    const body = new FormData();
    body.append('category', threatType);
    body.append('description', validation.sanitized);
    body.append('url', url);
    const button = document.getElementById('reportSubmit');
    if (button?.disabled) return;
    if (button) { button.disabled = true; button.textContent = 'Saving report…'; }
    const status = document.getElementById('reportStatus');
    if (status) status.textContent = '';
    try {
        const data = await postToServer('report.php', body);
        if (status) status.textContent = data.message;
        else alert(data.message);
        document.getElementById('reportForm').reset();
        loadAwarenessTable();
    } catch (error) {
        displayValidationErrors([error.message], 'reportForm');
    } finally {
        if (button) { button.disabled = false; button.textContent = 'Submit report →'; }
    }
}

async function resetAll() {
    const button = document.querySelector('[data-action="reset-all"]');
    const status = document.getElementById("resetStatus");
    if (button?.disabled) return;
    if (button) button.disabled = true;
    if (status) status.textContent = "Resetting…";
    analysisGeneration++;

    // 1) Wipe the database first; stay on the dashboard if that fails so nothing is silently left behind.
    try {
        await resetScanHistory();
    } catch (error) {
        if (status) status.textContent = error.message || "Could not reset the database.";
        if (button) button.disabled = false;
        return;
    }

    // 2) Clear every piece of text and result on the page.
    ["messageInput", "reportUrl", "threatContent", "awarenessSearch"].forEach(id => {
        const field = document.getElementById(id);
        if (field) field.value = "";
    });
    const scanMode = document.getElementById("scanMode");
    if (scanMode) scanMode.selectedIndex = 0;
    const threatType = document.getElementById("threatType");
    if (threatType) threatType.selectedIndex = 0;
    ["urlResultsList", "flagContainer", "detectorSources", "reportStatus", "detectorDetails", "scanHistoryBody"].forEach(id => {
        document.getElementById(id)?.replaceChildren();
    });
    document.getElementById("urlResults")?.classList.add("hidden");
    document.getElementById("resultCard")?.classList.add("hidden");
    clearValidationErrors();
    if (window.resetAssistant) window.resetAssistant();

    scanStats = { total: 0, highRisk: 0, legit: 0 };
    ["statTotalScans", "statHighRisk", "statLegit"].forEach(id => {
        const stat = document.getElementById(id);
        if (stat) stat.textContent = "0";
    });
    closeScanHistory();
    loadAwarenessTable();

    if (status) status.textContent = "";
    if (button) button.disabled = false;
    logSecurityEvent("SYSTEM_RESET", { timestamp: Date.now() });
    switchTab("homepage");
    window.scrollTo(0, 0);
}

/* ---------- Dashboard: Scan History panel (history.php) ---------- */

let historyReset = Promise.resolve();

function closeScanHistory() {
    const panel = document.getElementById("scanHistoryPanel");
    const toggle = document.getElementById("scanHistoryToggle");
    if (panel) panel.classList.add("hidden");
    if (toggle) toggle.setAttribute("aria-expanded", "false");
}

function toggleScanHistory() {
    const panel = document.getElementById("scanHistoryPanel");
    const toggle = document.getElementById("scanHistoryToggle");
    if (!panel) return;

    if (!panel.classList.contains("hidden")) {
        closeScanHistory();
        return;
    }
    panel.classList.remove("hidden");
    if (toggle) toggle.setAttribute("aria-expanded", "true");
    loadScanHistory();
}

async function loadScanHistory() {
    const body = document.getElementById("scanHistoryBody");
    if (!body) return;
    body.textContent = "Loading…";

    try {
        await historyReset;   // a reset in progress finishes first
        const response = await fetch("history.php", { credentials: "same-origin", headers: { Accept: "application/json" } });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.message || "Could not load the scan history.");
        body.innerHTML = data.html;   // built by history.php with every value escaped
    } catch (error) {
        body.textContent = error.message;
    }
}

function resetScanHistory() {
    const form = new FormData();
    form.append("action", "reset");
    historyReset = postToServer("history.php", form);
    return historyReset.then(() => {}, error => { historyReset = Promise.resolve(); throw error; });
}

function prepareReport(url = '', content = '', category = 'phishing') {
    switchTab('report');
    document.getElementById('reportUrl').value = url;
    document.getElementById('threatContent').value = content;
    document.getElementById('threatType').value = category;
    document.getElementById('reportStatus').textContent = 'Review the details below, then submit.';
    document.getElementById('reportUrl').focus();
}
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('reportAnalysis')?.addEventListener('click', () => {
        const text = document.getElementById('messageInput').value;
        const urls = window.DetectionEngine.urlsFrom(window.DetectionEngine.normalize(text));
        prepareReport(urls[0] || '', document.getElementById('scanMode').value === 'url' ? '' : text);
    });
});

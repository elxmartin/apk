let cachedHistory = [];
let cveChartInstance = null;
const API_BASE = window.API_BASE || 'https://apk.locamartin.workers.dev';

/**
 * Decryption Key Helper
 */
function getDecryptionKey() {
    let key = window.REPORT_ENCRYPTION_KEY || sessionStorage.getItem("REPORT_ENCRYPTION_KEY");
    if (!key) {
        key = prompt("Enter Decryption Key to inspect report:");
        if (key) {
            sessionStorage.setItem("REPORT_ENCRYPTION_KEY", key);
        }
    }
    return key;
}

function promptKeyAndFetch() {
    const key = prompt("Enter Report Decryption Key:");
    if (key) {
        sessionStorage.setItem("REPORT_ENCRYPTION_KEY", key);
        fetchStatus();
    }
}

function formatAppName(pkg) {
    if (!pkg) return "Unknown";
    const segments = pkg.split('.').filter(s => !['com', 'org', 'net', 'io', 'ch', 'nl', 'gp', 'twa'].includes(s.toLowerCase()));
    const targetSegment = segments.length > 0 ? segments[0] : pkg.split('.').pop();
    return targetSegment.charAt(0).toUpperCase() + targetSegment.slice(1);
}

async function fetchStatus() {
    const passKey = window.REPORT_ENCRYPTION_KEY || sessionStorage.getItem('REPORT_ENCRYPTION_KEY');
    try {
        const response = await fetch(`${API_BASE}/api/status?v=${Date.now()}`, { cache: 'no-store' });
        if (!response.ok) throw new Error(`Status request failed (${response.status}).`);
        
        const rawPayload = await response.text();
        let data = null;

        // Support plain JSON if unencrypted
        try {
            data = JSON.parse(rawPayload);
        } catch {
            // If worker returned raw encrypted payload, try direct ./status.json from Pages
            try {
                const directRes = await fetch(`./status.json?v=${Date.now()}`, { cache: 'no-store' });
                if (directRes.ok) {
                    data = await directRes.json();
                }
            } catch {}

            // Fallback to client-side decrypt if passKey is available
            if (!data && passKey && typeof decryptRawPayload === 'function') {
                try {
                    const decrypted = await decryptRawPayload(rawPayload, passKey);
                    data = JSON.parse(decrypted);
                } catch (decErr) {
                    console.warn("Decryption failed with stored key:", decErr);
                }
            }
        }

        if (data) {
            const stateBadge = document.getElementById('state');
            if (stateBadge) {
                const statusText = data.status || 'Idle';
                stateBadge.textContent = statusText;
                stateBadge.className = `badge ${statusText === 'Analyzing' ? 'badge-analyzing' : 'badge-idle'}`;
            }

            const currentAppEl = document.getElementById('current-app');
            if (currentAppEl) currentAppEl.textContent = data.current_app || 'None';

            const progressEl = document.getElementById('progress');
            if (progressEl) progressEl.textContent = `${data.completed || 0} / ${data.total || 0}`;

            cachedHistory = Array.isArray(data.history) ? data.history : [];
            updateRiskMetrics();
            renderTable();
            updateCveChart();
        } else {
            renderTable();
        }
    } catch (e) {
        console.error("Dashboard polling error:", e);
    }
}

function updateRiskMetrics() {
    let elevated = 0;
    let moderate = 0;
    cachedHistory.forEach(item => {
        const summary = item.cve_summary || {};
        elevated += (summary.critical || 0) + (summary.high || 0);
        moderate += summary.medium || 0;
    });
    const elevatedEl = document.getElementById('elevated-risks');
    const moderateEl = document.getElementById('moderate-risks');
    if (elevatedEl) elevatedEl.textContent = elevated;
    if (moderateEl) moderateEl.textContent = moderate;
}

function renderTable() {
    const list = document.getElementById('completed-apps');
    if (!list) return;

    list.innerHTML = '';
    const searchInput = document.getElementById('search');
    const query = (searchInput ? searchInput.value : '').toLowerCase().trim();

    const filtered = cachedHistory.filter(item => {
        const name = item.app_name || formatAppName(item.package);
        return !query || 
            (item.package && item.package.toLowerCase().includes(query)) ||
            (name && name.toLowerCase().includes(query));
    });

    if (filtered.length === 0) {
        list.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 1.5rem;">No matching records found.</td></tr>`;
        return;
    }

    filtered.forEach((item, index) => {
        const row = document.createElement('tr');
        const appName = item.app_name || formatAppName(item.package);

        row.innerHTML = `
            <td style="color: var(--text-muted); text-align: center;">${index + 1}</td>
            <td style="font-weight: 600; color: var(--text-main);">${appName}</td>
            <td><code>${item.package}</code></td>
            <td style="color: var(--text-muted);">${item.timestamp}</td>
            <td>
                <div class="report-actions">
                    <button class="report-btn" onclick="viewReport('${item.report_id}', '${item.package}', 'secrets.txt.enc')">Secrets</button>
                    <button class="report-btn" onclick="viewReport('${item.report_id}', '${item.package}', 'mobsfscan.json.enc')">Static Recon</button>
                    <button class="report-btn cve" onclick="viewReport('${item.report_id}', '${item.package}', 'cve.json.enc')">Trivy CVE</button>
                </div>
            </td>
        `;
        list.appendChild(row);
    });

    if (window.lucide) {
        lucide.createIcons();
    }
}

function updateCveChart() {
    const labels = [];
    const highCounts = [];
    const mediumCounts = [];
    const lowCounts = [];

    if (cachedHistory.length > 0) {
        cachedHistory.forEach(item => {
            labels.push(item.package);
            const summary = item.cve_summary || { critical: 0, high: 0, medium: 0, low: 0 };
            highCounts.push((summary.critical || 0) + (summary.high || 0));
            mediumCounts.push(summary.medium || 0);
            lowCounts.push(summary.low || 0);
        });
    }

    renderChartJS(labels, highCounts, mediumCounts, lowCounts);
}

function renderChartJS(labels = [], high = [], medium = [], low = []) {
    const chartCanvas = document.getElementById('cveChart');
    if (!chartCanvas) return;

    const ctx = chartCanvas.getContext('2d');
    if (cveChartInstance) cveChartInstance.destroy();

    cveChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.length > 0 ? labels : ['No Data'],
            datasets: [
                { label: 'High / Critical', data: high, backgroundColor: '#ef4444', borderRadius: 4 },
                { label: 'Medium', data: medium, backgroundColor: '#f59e0b', borderRadius: 4 },
                { label: 'Low', data: low, backgroundColor: '#38bdf8', borderRadius: 4 }
            ]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { stacked: true, grid: { color: 'rgba(51, 65, 85, 0.6)' }, ticks: { color: '#94a3b8' } },
                y: { stacked: true, grid: { display: false }, ticks: { color: '#f8fafc' } }
            },
            plugins: {
                legend: { position: 'top', labels: { color: '#f8fafc' } }
            }
        }
    });
}

async function viewReport(reportId, packageName, fileName) {
    const modal = document.getElementById('reportModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    if (!modal || !modalTitle || !modalBody) return;

    modalTitle.textContent = `${packageName} — ${fileName.replace('.enc', '')}`;
    modalBody.textContent = "Fetching report payload...";
    modal.style.display = "block";

    try {
        if (!reportId) throw new Error('This protected report needs to be migrated by the pipeline.');
        const workerUrl = `${API_BASE}/api/report?id=${encodeURIComponent(reportId)}&file=${encodeURIComponent(fileName)}&v=${Date.now()}`;
        const response = await fetch(workerUrl);

        if (!response.ok) {
            const errText = await response.text();
            throw new Error(`Worker Error (${response.status}): ${errText}`);
        }

        let payloadText = await response.text();

        // Check if payload is still encrypted (OpenSSL Salted__ Base64)
        if (payloadText.startsWith("U2FsdGVk")) {
            // Try fetching unencrypted version directly from GitHub Pages
            try {
                const unenc = fileName.replace('.enc', '');
                const directReport = await fetch(`./reports/${reportId}/${unenc}?v=${Date.now()}`);
                if (directReport.ok) {
                    payloadText = await directReport.text();
                }
            } catch {}
        }

        if (payloadText.startsWith("U2FsdGVk")) {
            const passKey = getDecryptionKey();
            if (!passKey) {
                modalBody.textContent = "Decryption passphrase is required to view encrypted reports.";
                return;
            }
            modalBody.textContent = "Decrypting payload client-side...";
            payloadText = await decryptRawPayload(payloadText, passKey);
        }

        try {
            const parsedJson = JSON.parse(payloadText);
            modalBody.textContent = JSON.stringify(parsedJson, null, 2);
        } catch (e) {
            modalBody.textContent = payloadText;
        }
    } catch (err) {
        modalBody.textContent = err.message || "Decryption failed or access denied.";
    }
}

function closeModal() {
    const modal = document.getElementById('reportModal');
    if (modal) modal.style.display = "none";
}

/**
 * Sidebar Navigation & Scroll Handler
 */
function setupSidebarNavigation() {
    const links = document.querySelectorAll('.sidebar-link');
    if (!links.length) return;

    function setActiveLink(hash) {
        const targetHash = hash || '#overview';
        links.forEach(link => {
            if (link.getAttribute('href') === targetHash) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });
    }

    links.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href').replace('#', '');
            const targetEl = document.getElementById(targetId);

            if (targetEl) {
                history.pushState(null, null, `#${targetId}`);
                setActiveLink(`#${targetId}`);

                targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

                // Luminous feedback ring
                targetEl.classList.add('section-highlight');
                setTimeout(() => {
                    targetEl.classList.remove('section-highlight');
                }, 1200);

                // Focus search box if navigating to records
                if (targetId === 'records') {
                    const searchInput = document.getElementById('search');
                    if (searchInput) {
                        setTimeout(() => searchInput.focus(), 300);
                    }
                }
            }
        });
    });

    if (window.location.hash) {
        setActiveLink(window.location.hash);
        const initialEl = document.getElementById(window.location.hash.replace('#', ''));
        if (initialEl) {
            setTimeout(() => {
                initialEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 150);
        }
    }

    // Scroll spy for automatic sidebar tab highlighting as user scrolls
    const sectionIds = ['overview', 'coverage', 'activity', 'records'];
    const sections = sectionIds.map(id => document.getElementById(id)).filter(Boolean);

    if (window.IntersectionObserver) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    setActiveLink(`#${entry.target.id}`);
                }
            });
        }, { threshold: 0.35 });

        sections.forEach(sec => observer.observe(sec));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    setupSidebarNavigation();
    if (window.lucide) {
        lucide.createIcons();
    }
    fetchStatus();
    setInterval(() => {
        fetchStatus();
    }, 5000); 
});
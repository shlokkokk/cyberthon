/**
 * ZeroRisk Sentinel - URL Analysis Engine
 * Last Audit: 2026-05-06
 * Version: 2.2-STABLE
 */
const BACKEND_URL = 'https://zerorisk-sentinel-backend.onrender.com';

const BACKEND_TIMEOUT = 25000;

// Main analyze function with timeout and fallback
async function analyzeURL() {
    const input = document.getElementById("urlInput");
    const url = input.value.trim();
    const deepScan = document.getElementById("deepScanToggle")?.checked || false;
    
    if (!url) {
        alert("Enter a URL to analyze");
        return;
    }
    
    // Show progress
    document.getElementById("scanningProgress").classList.remove("hidden");
    const progressFill = document.getElementById("progressFill");
    const progressText = document.getElementById("progressText");
    const currentFile = document.getElementById("currentFile");
    
    // Deep scan flow
    if (deepScan) {
        await performDeepScan(url, progressFill, progressText, currentFile);
        return;
    }
    
    // Regular scan flow (your existing code)
    const steps = [
        "Connecting to backend...",
        "Checking threat intelligence databases...",
        "Analyzing DNS and SSL...",
        "Compiling results..."
    ];
    
    let step = 0;
    const progressInterval = setInterval(() => {
        if (step < steps.length) {
            currentFile.textContent = steps[step];
            progressFill.style.width = Math.round(((step + 1) / steps.length) * 75) + "%";
            progressText.textContent = Math.round(((step + 1) / steps.length) * 75) + "%";
            step++;
        }
    }, 1000);
    
    const backendPromise = fetch(`${BACKEND_URL}/api/analyze-url`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: url})
    });
    
    const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Timeout')), BACKEND_TIMEOUT)
    );
    
    try {
        const response = await Promise.race([backendPromise, timeoutPromise]);
        clearInterval(progressInterval);
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error);
        }
        
        progressFill.style.width = "100%";
        progressText.textContent = "100%";
        currentFile.textContent = "Backend analysis complete!";
        
        await new Promise(r => setTimeout(r, 500));
        
        document.getElementById("scanningProgress").classList.add("hidden");
        sessionStorage.setItem("urlResults", JSON.stringify([data.data]));
        window.location.href = "results.html";
        
    } catch (err) {
        clearInterval(progressInterval);
        console.log("Backend unavailable, using local heuristics:", err.message);
        
        currentFile.textContent = "Backend timeout - switching to local analysis...";
        await new Promise(r => setTimeout(r, 800));
        
        document.getElementById("scanningProgress").classList.add("hidden");
        performLocalURLAnalysis(url);
    }
}

// Deep Scan via urlscan.io
async function performDeepScan(url, progressFill, progressText, currentFile) {
    progressFill.style.width = "10%";
    progressText.textContent = "10%";
    currentFile.textContent = "Submitting to sandbox...";
    
    try {
        const submitRes = await fetch(`${BACKEND_URL}/api/urlscan/submit`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url})
        });
        
        const submitData = await submitRes.json();
        
        if (!submitData.success) {
            throw new Error(submitData.error || "Failed to submit");
        }
        
        const scanId = submitData.scan_id;
        progressFill.style.width = "20%";
        progressText.textContent = "20%";
        
        currentFile.textContent = "Sandbox analyzing... (wait 20-40s)";
        
        const maxAttempts = 30; // 60 seconds max
        const pollInterval = 2000; // 2 seconds
        
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
            const progress = 20 + Math.round((attempt / maxAttempts) * 75);
            progressFill.style.width = progress + "%";
            progressText.textContent = progress + "%";
            
            await new Promise(r => setTimeout(r, pollInterval));
            
            const resultRes = await fetch(`${BACKEND_URL}/api/urlscan/result/${scanId}`);
            const resultData = await resultRes.json();
            
            // SUCCESS
            if (resultData.success && resultData.status === 'completed') {
                progressFill.style.width = "100%";
                progressText.textContent = "100%";
                currentFile.textContent = "Complete!";
                
                await new Promise(r => setTimeout(r, 500));
                document.getElementById("scanningProgress").classList.add("hidden");
                
                sessionStorage.setItem("urlResults", JSON.stringify([resultData]));
                window.location.href = "results.html";
                return;
            }
            
            // FAILED
            if (resultData.status === 'failed') {
                throw new Error(resultData.error || "Failed");
            }
            
            currentFile.textContent = `Analyzing... (${attempt + 1}/${maxAttempts})`;
        }
        
        throw new Error("Timeout - try again");
        
    } catch (err) {
        console.log("Deep scan failed:", err.message);
        currentFile.textContent = "Falling back to regular scan...";
        await new Promise(r => setTimeout(r, 1000));
        document.getElementById("deepScanToggle").checked = false;
        await analyzeURL();
    }
}
 
// Local heuristic analysis (fallback)
function performLocalURLAnalysis(url) {
    let parsed, hostname, score = 0, findings = [];
    
    try {
        parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
        hostname = parsed.hostname.toLowerCase();
    } catch(e) {
        alert("Invalid URL format");
        return;
    }
    
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        score += 30;
        findings.push({description: "Uses raw IP address instead of domain", severity: "high", type: "ip_url"});
    }
    
    if (/bit\.ly|tinyurl|t\.co|ow\.ly|cutt\.ly|rb\.gy/i.test(url)) {
        score += 25;
        findings.push({description: "URL shortener hides final destination", severity: "high", type: "shortener"});
    }
    
    if (/login|verify|secure|bank|password|account|update|confirm|urgent/i.test(url)) {
        score += 20;
        findings.push({description: "Contains phishing-related keywords", severity: "medium", type: "phishing_words"});
    }
    
    if (/\.(xyz|tk|ml|ga|cf|top|icu)$/i.test(url)) {
        score += 20;
        findings.push({description: "Uses high-risk TLD", severity: "medium", type: "risky_tld"});
    }
    
    if (!url.startsWith('https')) {
        score += 15;
        findings.push({description: "Connection not encrypted (no HTTPS)", severity: "medium", type: "no_https"});
    }
    
    if (parsed.pathname.split('/').length > 5) {
        score += 10;
        findings.push({description: "Unusually deep URL path", severity: "low", type: "long_path"});
    }
    
    if (url.length > 100) {
        score += 5;
        findings.push({description: "Unusually long URL", severity: "low", type: "long_url"});
    }
    
    score = Math.min(score, 100);
    let level = score >= 70 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : score > 0 ? 'low' : 'safe';
    
    const result = {
        url: url,
        domain: hostname,
        threat_score: score,
        threat_level: level,
        findings: findings,
        explanation: generateLocalExplanation(findings, level, url),
        services: {note: "Local heuristic analysis - backend unavailable"},
        backend_based: false,
        deep_scan: false,
        scan_time: new Date().toISOString()
    };
    
    sessionStorage.setItem("urlResults", JSON.stringify([result]));
    window.location.href = "results.html";
}

function generateLocalExplanation(findings, level, url) {
    const map = {
        safe: "No significant threats detected via local heuristics.",
        low: "Minor suspicious patterns detected.",
        medium: "Multiple suspicious indicators present.",
        high: "Strong correlation with malicious behavior.",
        critical: "High-confidence malicious indicators detected."
    };
    
    let text = `Local analysis of "${url}":\n\n`;
    findings.forEach(f => {
        text += `• ${f.description}\n`;
    });
    text += `\n${map[level]} (Local analysis - backend unavailable)`;
    return text;
}

function setScanMode(mode) {
    const liveBtn = document.getElementById('liveModeBtn');
    const demoBtn = document.getElementById('demoModeBtn');
    const demoUrlsSection = document.getElementById('demoUrls');
    
    if (mode === 'live') {
        liveBtn.className = 'px-4 py-2 rounded-lg bg-blue-600 text-white font-medium';
        demoBtn.className = 'px-4 py-2 rounded-lg bg-gray-700 text-gray-300 font-medium hover:bg-gray-600';
        demoUrlsSection.classList.add('hidden');
    } else {
        demoBtn.className = 'px-4 py-2 rounded-lg bg-blue-600 text-white font-medium';
        liveBtn.className = 'px-4 py-2 rounded-lg bg-gray-700 text-gray-300 font-medium hover:bg-gray-600';
        demoUrlsSection.classList.remove('hidden');
    }
}

function runDemoURL(demoTypeOrUrl) {
    const input = document.getElementById("urlInput");
    if (!input) return;

    const demoURLs = {
        'google-phish': 'https://secure-google-login.xyz/verify?token=abc123&session=fake',
        'paypal-phish': 'http://paypal-alerts-login.com/secure/verify/account',
        'ip-suspicious': 'http://192.168.0.1/auth/login.php?redirect=evil',
        'shortener': 'https://bit.ly/3xAmPlE',
        'mixed-signals': 'http://amazon-security-verify.tk/login?urgent=true'
    };

    const url = demoURLs[demoTypeOrUrl] || demoTypeOrUrl;
    
    if (!url) return;

    input.value = url;
    analyzeURL();
}
// Attach click listener to analyze button
document.addEventListener("DOMContentLoaded", function() {
    const btn = document.getElementById("analyzeBtn");
    if (btn) {
        btn.addEventListener("click", analyzeURL);
    }
});

// Info Modal Functions
const modalInfo = {
  deepScan: {
    title: "Deep Scan Mode",
    content: "Deep Scan performs comprehensive sandboxed analysis by visiting the URL in an isolated environment. This captures real-time page behavior, network activity, and potential threats. Takes 15-30 seconds but provides maximum security assurance."
  }
};

function showInfoModal(key) {
  const modal = document.getElementById('infoModal');
  const title = document.getElementById('modalTitle');
  const content = document.getElementById('modalContent');
  title.textContent = modalInfo[key].title;
  content.textContent = modalInfo[key].content;
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeInfoModal() {
  const modal = document.getElementById('infoModal');
  modal.classList.add('hidden');
  document.body.style.overflow = '';
}

document.addEventListener('click', (e) => {
  if (e.target.id === 'infoModal') closeInfoModal();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeInfoModal();
});
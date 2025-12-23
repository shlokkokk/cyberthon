// These are heuristic signals not proof of malicious intent.

// ai gen explanation for findings
 
function generateHeuristicExplanation(findings, threatLevel, url) {
  const explanationMap = {
    "Uses URL shortener (destination obfuscated)":
      "URL shorteners hide the final destination, preventing users from seeing the real domain. Attackers often use them to conceal malicious links.",

    "Contains phishing-related keywords":
      "Urgency-based keywords are commonly used in phishing to pressure users into acting quickly without verifying legitimacy.",

    "Brand name appears in subdomain — common phishing evasion technique":
      "Attackers embed trusted brand names inside subdomains to trick users into overlooking the actual malicious domain.",

    "Uses high-risk TLD often associated with newly registered domains":
      "Certain TLDs are statistically abused more often due to low cost and minimal verification.",

    "Uses raw IP address instead of domain":
      "IP-based URLs avoid domain reputation checks and hide ownership, which is common in malicious infrastructure.",

    "Contains sensitive query parameters commonly abused in phishing":
      "Parameters like tokens or session IDs may indicate attempts to capture authentication data."
  };

  let text = `ZeroRisk Sentinel analyzed "${url}" and identified ${
    findings.length
  } heuristic indicator${findings.length !== 1 ? "s" : ""}.\n\n`;

  findings.forEach((f) => {
    text += `• ${f}: ${
      explanationMap[f] ||
      "This pattern matches known social-engineering or obfuscation techniques."
    }\n`;
  });

  const riskMap = {
    safe: "Overall risk is minimal.",
    low: "Low risk indicators detected.",
    medium: "Multiple suspicious indicators detected.",
    high: "Strong correlation with phishing or malicious behavior.",
    critical: "High-confidence malicious intent detected."
  };

  text += `\n${riskMap[threatLevel]}\n`;
  text +=
    "This analysis is heuristic-based and does not guarantee malicious intent.";

  return text;
}

const PHISHING_KEYWORDS =
  /(login|verify|secure|update|account|bank|signin|password|reset|confirm|suspended|locked|urgent)/i;

const BRAND_KEYWORDS =
  /(google|paypal|amazon|microsoft|apple|netflix|facebook|instagram|whatsapp|telegram|bank)/i;

const URL_SHORTENERS = /(bit\.ly|tinyurl|t\.co|ow\.ly|cutt\.ly|rb\.gy)/i;

const HIGH_RISK_TLDS = /\.(xyz|top|icu|tk|ml|ga)$/i;

const SUSPICIOUS_PARAMS =
  /(token|session|auth|redirect|callback|login|password)/i;

function analyzeURL() {
  const input = document.getElementById("urlInput");
  const url = input.value.trim();

  if (!url) {
    alert("Enter a URL");
    return;
  }

  let score = 0;
  let findings = [];

  // Rule 1: IP-based URL
  if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
    score += 30;
    findings.push("Uses raw IP address instead of domain");
  }

  // Rule 2: Suspicious keywords
  if (PHISHING_KEYWORDS.test(url)) {
    score += 20;
    findings.push("Contains phishing-related keywords");
  }

  // Rule 3: URL shortener
  let shortenerDetected = false;

  if (URL_SHORTENERS.test(url)) {
    score += 25;
    shortenerDetected = true;
    findings.push("Uses URL shortener (destination obfuscated)");
  }

  // Rule 4: No HTTPS
  if (!url.startsWith("https://")) {
    score += 15;
    findings.push("Connection is not HTTPS");
  }
  // Rule 5: High-risk TLD (simulated domain age risk)
  if (HIGH_RISK_TLDS.test(url)) {
    score += 25;
    findings.push(
      "Uses high-risk TLD often associated with newly registered domains"
    );
  }
  // Rule 6: Lookalike domain using numbers
  const domainPart = url
    .replace("https://", "")
    .replace("http://", "")
    .split("/")[0];
  if (/[0-9]/.test(domainPart)) {
    score += 15;
    findings.push(
      "Possible lookalike domain using numbers to mimic trusted brands"
    );
  }
  // Rule 7: Excessive URL path depth
  const pathDepth = url.split("/").length - 3;
  if (pathDepth >= 5) {
    score += 10;
    findings.push("Unusually deep URL path structure");
  }
  // Rule 8: Suspicious query parameters
  if (SUSPICIOUS_PARAMS.test(url)) {
    score += 20;
    findings.push(
      "Contains sensitive query parameters commonly abused in phishing"
    );
  }
  // Rule 9: Brand impersonation ONLY when combined with risk signals
  if (
    BRAND_KEYWORDS.test(url) &&
    (PHISHING_KEYWORDS.test(url) ||
      HIGH_RISK_TLDS.test(url) ||
      URL_SHORTENERS.test(url))
  ) {
    score += 15;
    findings.push(
      "Brand name combined with phishing patterns — possible impersonation"
    );
  }
  // Rule 10 Subdomain(brand buried in subdomain)
  const hostname = domainPart.toLowerCase();
  if (hostname.split(".").length > 3 && BRAND_KEYWORDS.test(hostname)) {
    score += 20;
    findings.push(
      "Brand name appears in subdomain — common phishing evasion technique"
    );
  }

  score = Math.min(score, 100);

  // Threat level
  let threatLevel = "safe";

  if (score >= 70) threatLevel = "critical";
  else if (score >= 50) threatLevel = "high";
  else if (score >= 25) threatLevel = "medium";
  else if (score > 0) threatLevel = "low";
  // Enforce minimum risk for URL shorteners
  if (shortenerDetected && threatLevel === "low") {
    threatLevel = "medium";
  }

  if (findings.length === 0) {
    findings.push("No obvious heuristic issues detected");
  }

  const explanation = generateHeuristicExplanation(findings, threatLevel, url);

  const result = {
    url,
    threatScore: score,
    threatLevel,
    findings,
    explanation,
  };

  sessionStorage.setItem("urlResults", JSON.stringify([result]));

  setTimeout(() => {
    window.location.href = "results.html";
  }, 600);
}

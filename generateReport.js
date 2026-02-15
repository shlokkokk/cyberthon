const REPORT_VERSION = "2.2.0";
let selectedFormat = null;

//  CHART DATA CALCULATION 

function calculateReportChartData() {
  const fileData = JSON.parse(sessionStorage.getItem("analysisResults") || "[]");
  
  let safe = 0, warning = 0, critical = 0, totalScore = 0;
  let sandboxCount = 0;

  fileData.forEach((file) => {
    if (file.threatLevel === "safe") safe++;
    else if (file.threatLevel === "low" || file.threatLevel === "medium") warning++;
    else if (file.threatLevel === "high" || file.threatLevel === "critical") critical++;
    totalScore += file.threatScore || 0;
    if (file.deep_scan || file.sandbox_data) sandboxCount++;
  });

  const avgThreat = fileData.length ? Math.round(totalScore / fileData.length) : 0;
  return { 
    safe, 
    warning, 
    critical, 
    avgScore: Math.max(0, 100 - avgThreat),
    totalFiles: fileData.length,
    sandboxCount
  };
}

function calculateURLStats() {
  const urlData = JSON.parse(sessionStorage.getItem("urlResults") || "[]");
  
  let safe = 0, warning = 0, critical = 0;
  let backendBased = 0, localBased = 0, deepScan = 0;

  urlData.forEach((url) => {
    if (url.threatLevel === "safe" || url.threat_level === "safe") safe++;
    else if (url.threatLevel === "low" || url.threatLevel === "medium" || 
             url.threat_level === "low" || url.threat_level === "medium") warning++;
    else if (url.threatLevel === "high" || url.threatLevel === "critical" ||
             url.threat_level === "high" || url.threat_level === "critical") critical++;
    
    if (url.backend_based) backendBased++;
    else localBased++;
    
    if (url.deep_scan) deepScan++;
  });

  return {
    total: urlData.length,
    safe,
    warning,
    critical,
    backendBased,
    localBased,
    deepScan
  };
}

function openReportModal() {
  const modal = document.getElementById("reportModal");
  if (!modal) return;

  modal.style.opacity = "1";
  modal.style.visibility = "visible";
  
  const modalContent = modal.querySelector("div");
  if (modalContent) {
    modalContent.style.transform = "scale(1)";
    modalContent.style.opacity = "1";
  }

  selectedFormat = null;
  document.querySelectorAll(".format-opt").forEach((el) => {
    el.style.borderColor = "rgba(0,212,255,0.2)";
    el.style.background = "rgba(255,255,255,0.03)";
    el.style.boxShadow = "none";
    el.style.transform = "scale(1)";
  });

  const genBtn = document.getElementById("genReportBtn");
  if (genBtn) {
    genBtn.disabled = true;
    genBtn.style.opacity = "0.4";
    genBtn.style.cursor = "not-allowed";
  }
}

function closeReportModal() {
  const modal = document.getElementById("reportModal");
  if (!modal) return;

  modal.style.opacity = "0";
  modal.style.visibility = "hidden";
  
  const modalContent = modal.querySelector("div");
  if (modalContent) {
    modalContent.style.transform = "scale(0.9)";
    modalContent.style.opacity = "0";
  }
}

function selectFormat(format) {
  selectedFormat = format;

  document.querySelectorAll(".format-opt").forEach((el) => {
    el.style.borderColor = "rgba(0,212,255,0.2)";
    el.style.background = "rgba(255,255,255,0.03)";
    el.style.boxShadow = "none";
    el.style.transform = "scale(1)";
  });

  const selectedEl = document.getElementById("fmt-" + format);
  if (selectedEl) {
    selectedEl.style.borderColor = "#00d4ff";
    selectedEl.style.background = "rgba(0,212,255,0.15)";
    selectedEl.style.boxShadow = "0 0 20px rgba(0,212,255,0.3), inset 0 0 20px rgba(0,212,255,0.05)";
    selectedEl.style.transform = "scale(1.02)";
  }

  const genBtn = document.getElementById("genReportBtn");
  if (genBtn) {
    genBtn.disabled = false;
    genBtn.style.opacity = "1";
    genBtn.style.cursor = "pointer";
  }
}

//  MAIN REPORT GENERATION 

async function generateSelectedReport() {
  if (!selectedFormat) return;

  const fileData = JSON.parse(sessionStorage.getItem("analysisResults") || "[]");
  const urlData = JSON.parse(sessionStorage.getItem("urlResults") || "[]");

  if (fileData.length === 0 && urlData.length === 0) {
    showNotification("No scan data available. Please scan files or URLs first.", "warning");
    closeReportModal();
    return;
  }

  const btn = document.getElementById("genReportBtn");
  const originalText = btn ? btn.innerHTML : "Generate Report";

  if (btn) {
    btn.innerHTML = '<span class="animate-pulse">Generating...</span>';
    btn.disabled = true;
  }

  try {
    if (selectedFormat === "json") {
      await generateJSONReport(fileData, urlData);
    } else if (selectedFormat === "pdf") {
      await generatePDFReport(fileData, urlData);
    }

    closeReportModal();
    showNotification("Report generated successfully!", "success");
  } catch (error) {
    console.error("Report generation error:", error);
    showNotification("Failed to generate report: " + error.message, "error");
  } finally {
    if (btn) {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }
}

//  JSON REPORT 

async function generateJSONReport(fileData, urlData) {
  const chartData = calculateReportChartData();
  const urlStats = calculateURLStats();

  const reportData = {
    reportMetadata: {
      generatedAt: new Date().toISOString(),
      toolName: "ZeroRisk Sentinel",
      version: REPORT_VERSION,
      reportType: "Security Analysis Summary",
      reportId: generateReportId()
    },
    executiveSummary: {
      generatedAt: new Date().toLocaleString(),
      totalScans: fileData.length + urlData.length,
      filesScanned: fileData.length,
      urlsScanned: urlData.length,
      filesWithSandbox: chartData.sandboxCount,
      urlsWithDeepScan: urlStats.deepScan,
      overallSecurityScore: chartData.avgScore,
      threatBreakdown: {
        safe: chartData.safe + urlStats.safe,
        warning: chartData.warning + urlStats.warning,
        critical: chartData.critical + urlStats.critical
      },
      riskAssessment: generateRiskAssessmentText(fileData, urlData)
    },
    fileAnalysis: {
      scanned: fileData.length > 0,
      totalFiles: fileData.length,
      sandboxScans: chartData.sandboxCount,
      statistics: {
        safe: chartData.safe,
        warning: chartData.warning,
        critical: chartData.critical,
        securityScore: chartData.avgScore
      },
      files: fileData.length > 0 ? fileData.map((file) => ({
        name: file.name,
        size: file.size,
        sizeFormatted: formatBytes(file.size),
        type: file.type,
        threatLevel: file.threatLevel,
        threatScore: file.threatScore,
        hashes: file.hashes || null,
        entropy: file.entropy || null,
        fileType: file.fileType || null,
        virustotal: file.virustotal || null,
        deepScan: file.deep_scan || false,
        sandboxData: file.sandbox_data || null,
        keyloggerDetected: file.keyloggerDetected || false,
        malwareDetected: file.malwareDetected || false,
        extensionMismatch: file.extensionMismatch || false,
        riskExposure: file.riskExposure || "unknown",
        spywareProfile: file.spywareProfile || null,
        findings: file.findings || [],
        apkAnalysis: file.apkAnalysis || null,
        scanTimestamp: file.lastModified || null
      })) : []
    },
    urlAnalysis: {
      scanned: urlData.length > 0,
      totalURLs: urlData.length,
      deepScans: urlStats.deepScan,
      statistics: urlStats,
      urls: urlData.length > 0 ? urlData.map((url) => ({
        url: url.url,
        domain: url.domain,
        threatLevel: url.threat_level || url.threatLevel,
        threatScore: url.threat_score || url.threatScore,
        backendBased: url.backend_based || false,
        deepScan: url.deep_scan || false,
        services: url.services || {},
        urlscanData: url.urlscan_data || null,
        findings: url.findings || [],
        explanation: url.explanation || "",
        scanTimestamp: url.scan_time
      })) : []
    },
    recommendations: generateRecommendations(fileData, urlData)
  };

  const jsonStr = JSON.stringify(reportData, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = `zerorisk-report-${formatTimestamp()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

//  PDF REPORT 

async function generatePDFReport(fileData, urlData) {
  const { jsPDF } = window.jspdf;
  if (!jsPDF) throw new Error("PDF library not loaded");

  const doc = new jsPDF({ unit: "mm", format: "a4" });

  //  PAGE METRICS 
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();

  const M = {
    left: 14,
    right: 14,
    top: 16,
    bottom: 14,
    headerH: 12,
    footerH: 10
  };

  const contentLeft = M.left;
  const contentRight = pageWidth - M.right;
  const contentWidth = contentRight - contentLeft;

  // flow cursor
  let y = M.top + M.headerH + 6;

  //  DATA 
  const chartData = calculateReportChartData();
  const urlStats = calculateURLStats();

  //  THEME 
  const COLORS = {
    bg: [10, 10, 10],
    panel: [20, 20, 20],
    panel2: [26, 26, 26],
    border: [55, 65, 81],
    text: [245, 245, 245],
    muted: [170, 170, 170],
    faint: [120, 120, 120],

    primary: [0, 212, 255],
    good: [0, 255, 136],
    warn: [255, 107, 53],
    bad: [220, 20, 60],
    purple: [168, 85, 247]
  };

  const FONT = {
    base: "helvetica",
    mono: "courier" // built-in fallback; keeps hashes readable
  };

  const S = {
    h1: 20,
    h2: 14,
    h3: 11,
    body: 9,
    small: 8,
    tiny: 7,

    lh: 1.25,      // line-height multiplier
    pad: 5,        // card padding
    gap: 4,        // vertical gap
    radius: 2.5
  };

  //  HELPERS 
  const setFont = (family = FONT.base, style = "normal", size = S.body) => {
    doc.setFont(family, style);
    doc.setFontSize(size);
  };

  const setText = (rgb) => doc.setTextColor(...rgb);
  const setDraw = (rgb) => doc.setDrawColor(...rgb);
  const setFill = (rgb) => doc.setFillColor(...rgb);

  const lineHeight = (size) => (size * 0.3528) * S.lh; // approx pt->mm then * lh

  const split = (text, maxW, size = S.body, family = FONT.base, style = "normal") => {
    setFont(family, style, size);
    return doc.splitTextToSize(String(text || ""), maxW);
  };

  const safeStr = (v, fallback = "N/A") => {
    if (v === null || v === undefined) return fallback;
    const s = String(v);
    return s.trim() ? s : fallback;
  };

  const threatColor = (level) => {
    switch (level) {
      case "safe": return COLORS.good;
      case "low": return COLORS.primary;
      case "medium": return COLORS.warn;
      case "high":
      case "critical": return COLORS.bad;
      default: return COLORS.muted;
    }
  };

  const ensureSpace = (needed = 20) => {
    const bottomLimit = pageHeight - M.bottom - M.footerH;
    if (y + needed <= bottomLimit) return false;

    doc.addPage();
    drawHeader();
    y = M.top + M.headerH + 6;
    return true;
  };

  const drawHeader = () => {
    // top bar
    setFill(COLORS.bg);
    doc.rect(0, 0, pageWidth, M.headerH, "F");

    // thin accent line
    setDraw(COLORS.primary);
    doc.setLineWidth(0.6);
    doc.line(0, M.headerH, pageWidth, M.headerH);

    // title
    setFont(FONT.base, "bold", 9);
    setText(COLORS.primary);
    doc.text("ZeroRisk Sentinel — Security Analysis Report", M.left, 8);

    // generated timestamp on right
    setFont(FONT.base, "normal", 7);
    setText(COLORS.muted);
    doc.text(new Date().toLocaleString(), pageWidth - M.right, 8, { align: "right" });
  };

  const drawFooterAllPages = () => {
    const totalPages = doc.internal.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);

      const y0 = pageHeight - M.footerH;

      setFill(COLORS.panel2);
      doc.rect(0, y0, pageWidth, M.footerH, "F");

      setDraw(COLORS.primary);
      doc.setLineWidth(0.3);
      doc.line(M.left, y0, pageWidth - M.right, y0);

      setFont(FONT.base, "normal", 7);
      setText(COLORS.muted);
      doc.text(
        `ZeroRisk Sentinel v${REPORT_VERSION} · Page ${i} of ${totalPages}`,
        pageWidth / 2,
        y0 + 6,
        { align: "center" }
      );
    }
  };

  const sectionTitle = (title) => {
    ensureSpace(18);
    setFont(FONT.base, "bold", S.h2);
    setText(COLORS.primary);
    doc.text(title, contentLeft, y);
    y += 2;

    setDraw(COLORS.border);
    doc.setLineWidth(0.3);
    doc.line(contentLeft, y + 2.2, contentRight, y + 2.2);

    y += 8;
  };

  const card = (height, fill = COLORS.panel) => {
    ensureSpace(height + 2);
    setFill(fill);
    setDraw(COLORS.border);
    doc.setLineWidth(0.25);
    doc.roundedRect(contentLeft, y, contentWidth, height, S.radius, S.radius, "FD");
  };

  const writeBlock = (lines, x, y0, size = S.body, color = COLORS.text, family = FONT.base, style = "normal") => {
    setFont(family, style, size);
    setText(color);
    const lh = lineHeight(size);
    doc.text(lines, x, y0);
    return y0 + (lines.length * lh);
  };

  const kvRow = (label, value, x, y0, colW) => {
    // label (muted), value (white)
    setFont(FONT.base, "normal", S.small);
    setText(COLORS.muted);
    doc.text(label, x, y0);

    setFont(FONT.base, "bold", S.small);
    setText(COLORS.text);
    const valLines = split(value, colW - 20, S.small, FONT.base, "bold");
    const lh = lineHeight(S.small);
    doc.text(valLines, x + 20, y0);
    return y0 + (valLines.length * lh);
  };

  const badge = (text, x, y0, rgb, bgAlpha = 0.12) => {
    // simple pill badge
    const paddingX = 2.2;
    const paddingY = 1.2;

    setFont(FONT.base, "bold", 7);
    const w = doc.getTextWidth(text) + paddingX * 2;
    const h = 4.8;

    // background using low opacity via fill trick (jsPDF has no alpha without GState reliably everywhere)
    // We'll approximate "soft" by using a darker panel and border in rgb
    setFill([Math.min(255, rgb[0] * 0.15 + 20), Math.min(255, rgb[1] * 0.15 + 20), Math.min(255, rgb[2] * 0.15 + 20)]);
    setDraw(rgb);
    doc.setLineWidth(0.2);
    doc.roundedRect(x, y0 - 3.5, w, h, 2.2, 2.2, "FD");

    setText(rgb);
    doc.text(text, x + paddingX, y0, { baseline: "middle" });
    return x + w + 2;
  };

  //  COVER PAGE 
  // Make cover page clean + centered (no fragile gradient loops)
  setFill(COLORS.bg);
  doc.rect(0, 0, pageWidth, pageHeight, "F");

  // accent top glow bar
  setFill([0, 212, 255]);
  doc.setGState && doc.setGState(new doc.GState({ opacity: 0.08 }));
  doc.rect(0, 0, pageWidth, 32, "F");
  doc.setGState && doc.setGState(new doc.GState({ opacity: 1 }));

  // title stack
  setFont(FONT.base, "bold", 28);
  setText(COLORS.text);
  doc.text("ZeroRisk Sentinel", pageWidth / 2, 60, { align: "center" });

  setFont(FONT.base, "normal", 13);
  setText(COLORS.primary);
  doc.text("Security Analysis Report", pageWidth / 2, 70, { align: "center" });

  // cover meta card
  const totalItems = fileData.length + urlData.length;
  const reportId = generateReportId(); // keep same function; previously it was called multiple times anyway

  const coverCardY = 92;
  const coverCardH = 52;
  setFill(COLORS.panel);
  setDraw(COLORS.border);
  doc.roundedRect(M.left + 18, coverCardY, pageWidth - (M.left + 18) * 2, coverCardH, 3, 3, "FD");

  setFont(FONT.base, "normal", 9);
  setText(COLORS.muted);
  doc.text(`Generated: ${new Date().toLocaleString()}`, pageWidth / 2, coverCardY + 14, { align: "center" });
  doc.text(`Version: ${REPORT_VERSION}`, pageWidth / 2, coverCardY + 22, { align: "center" });
  doc.text(`Report ID: ${reportId}`, pageWidth / 2, coverCardY + 30, { align: "center" });

  setFont(FONT.base, "bold", 10);
  setText(COLORS.text);
  doc.text(`Items Scanned: ${totalItems}  (Files: ${fileData.length}, URLs: ${urlData.length})`, pageWidth / 2, coverCardY + 42, { align: "center" });

  // score hero (only if file stats exist like your old logic)
  if (fileData.length > 0) {
    const score = chartData.avgScore;
    const scoreRgb = score >= 80 ? COLORS.good : score >= 60 ? COLORS.warn : COLORS.bad;

    setFont(FONT.base, "bold", 11);
    setText(COLORS.text);
    doc.text("OVERALL SECURITY SCORE", pageWidth / 2, 162, { align: "center" });

    // ring
    doc.setLineWidth(1.2);
    setDraw(scoreRgb);
    doc.circle(pageWidth / 2, 182, 14);

    setFont(FONT.base, "bold", 18);
    setText(scoreRgb);
    doc.text(String(Math.round(score)), pageWidth / 2, 187, { align: "center" });

    setFont(FONT.base, "normal", 9);
    setText(COLORS.muted);
    doc.text(`Safe: ${chartData.safe}  ·  Warning: ${chartData.warning}  ·  Critical: ${chartData.critical}`, pageWidth / 2, 202, { align: "center" });
  } else if (totalItems === 0) {
    setFont(FONT.base, "bold", 12);
    setText(COLORS.warn);
    doc.text("NO SCAN DATA AVAILABLE", pageWidth / 2, 170, { align: "center" });

    setFont(FONT.base, "normal", 9);
    setText(COLORS.muted);
    doc.text("Scan files or URLs to generate a complete report.", pageWidth / 2, 180, { align: "center" });
  }

  // confidentiality strip
  setFill(COLORS.primary);
  doc.rect(0, pageHeight - 26, pageWidth, 10, "F");
  setFont(FONT.base, "bold", 9);
  setText(COLORS.bg);
  doc.text("CONFIDENTIAL SECURITY REPORT", pageWidth / 2, pageHeight - 21, { align: "center" });

  setFont(FONT.base, "normal", 7);
  setText(COLORS.muted);
  doc.text("Generated by ZeroRisk Sentinel Advanced Security Scanner", pageWidth / 2, pageHeight - 10, { align: "center" });

  //  CONTENT PAGES 
  doc.addPage();
  drawHeader();
  y = M.top + M.headerH + 6;

  // EXECUTIVE SUMMARY
  sectionTitle("Executive Summary");

  // Summary card: two-column grid (auto-wrapped)
  {
    const leftW = (contentWidth - 6) / 2;
    const rightW = leftW;

    // determine card height dynamically
    const linesLeft = [
      `Total Items: ${totalItems}`,
      `Files Scanned: ${fileData.length}`,
      `URLs Scanned: ${urlData.length}`
    ];

    const linesRight = [];
    if (fileData.length > 0) linesRight.push(`Security Score: ${chartData.avgScore}/100`);
    if (chartData.sandboxCount > 0) linesRight.push(`File Sandboxes: ${chartData.sandboxCount}`);
    if (urlStats.deepScan > 0) linesRight.push(`URL Deep Scans: ${urlStats.deepScan}`);

    const lh = lineHeight(S.body);
    const h = Math.max(26, (Math.max(linesLeft.length, linesRight.length) * lh) + S.pad * 2 + 6);

    card(h);

    let x1 = contentLeft + S.pad;
    let x2 = contentLeft + S.pad + leftW + 6;

    let y0 = y + 8;

    setFont(FONT.base, "bold", 10);
    setText(COLORS.text);
    doc.text("Overview", x1, y0);
    doc.text("Scan Enhancements", x2, y0);

    y0 += 6;

    setFont(FONT.base, "normal", S.body);
    setText(COLORS.muted);
    linesLeft.forEach((t, i) => doc.text(t, x1, y0 + i * lh));
    linesRight.length
      ? linesRight.forEach((t, i) => doc.text(t, x2, y0 + i * lh))
      : doc.text("—", x2, y0);

    y += h + 8;
  }

  // Assessment Details (auto height + page breaks)
  {
    const assessment = generateRiskAssessmentText(fileData, urlData);
    const maxW = contentWidth - S.pad * 2;
    const lines = split(assessment, maxW, S.body, FONT.base, "normal");
    const h = Math.min(120, (lines.length * lineHeight(S.body)) + S.pad * 2 + 10);

    ensureSpace(h + 6);
    setFont(FONT.base, "bold", 10);
    setText(COLORS.primary);
    doc.text("Assessment Details", contentLeft, y);

    y += 6;

    card(h, COLORS.panel);
    writeBlock(lines, contentLeft + S.pad, y + 8, S.body, COLORS.text, FONT.base, "normal");

    y += h + 10;
  }

  // THREAT DISTRIBUTION (compact KPI card)
  {
    sectionTitle("Threat Distribution");

    const totalSafe = chartData.safe + urlStats.safe;
    const totalWarn = chartData.warning + urlStats.warning;
    const totalCrit = chartData.critical + urlStats.critical;

    const kpiH = 26;
    card(kpiH, COLORS.panel);

    const col = (contentWidth - S.pad * 2) / 3;
    const baseY = y + 10;

    const drawKpi = (idx, label, value, rgb) => {
      const x = contentLeft + S.pad + idx * col;

      setFont(FONT.base, "bold", 14);
      setText(rgb);
      doc.text(String(value), x, baseY);

      setFont(FONT.base, "normal", 8);
      setText(COLORS.muted);
      doc.text(label, x, baseY + 6);
    };

    drawKpi(0, "Safe", totalSafe, COLORS.good);
    drawKpi(1, "Warnings", totalWarn, COLORS.warn);
    drawKpi(2, "Critical", totalCrit, COLORS.bad);

    y += kpiH + 10;
  }

  //  FILE ANALYSIS 
  doc.addPage();
  drawHeader();
  y = M.top + M.headerH + 6;
  sectionTitle("File Security Analysis");

  if (fileData.length === 0) {
    const h = 22;
    card(h);
    setFont(FONT.base, "bold", 10);
    setText(COLORS.muted);
    doc.text("No files were scanned during this session.", contentLeft + S.pad, y + 11);
    y += h + 8;
  } else {
    fileData.forEach((file, idx) => {
      const level = safeStr(file.threatLevel, "unknown");
      const tc = threatColor(level);
      const hasSandbox = !!(file.deep_scan || file.sandbox_data);

      // Build variable-length blocks
      const name = safeStr(file.name, "Unknown File");
      const scoreText = `Threat Score: ${file.threatScore || 0}/100`;
      const sizeText = `Size: ${formatBytes(file.size)}`;
      const typeText = `Type: ${safeStr(file.type, "unknown")}`;

      const flags = [];
      if (file.keyloggerDetected) flags.push("Keylogger");
      if (file.extensionMismatch) flags.push("Extension Spoofing");
      if (file.malwareDetected) flags.push("Malware Indicators");
      if (hasSandbox) flags.push("Sandboxed");

      const profile = file.spywareProfile || null;
      const findings = Array.isArray(file.findings) ? file.findings : [];
      const sha = file.hashes?.sha256 ? String(file.hashes.sha256) : null;

      // Estimate height precisely using wrapping
      const innerW = contentWidth - S.pad * 2;
      const lhB = lineHeight(S.body);
      const lhS = lineHeight(S.small);

      const nameLines = split(`${idx + 1}. ${name}`, innerW - 50, 10, FONT.base, "bold");
      const flagLine = flags.length ? flags.join(" · ") : "—";
      const flagLines = split(flagLine, innerW, 8, FONT.base, "normal");

      const profileLines = profile
        ? [
            `Surveillance: ${profile.surveillance ? "Yes" : "No"}`,
            `Data Exfiltration: ${profile.dataExfiltration ? "Yes" : "No"}`,
            `Persistence: ${profile.persistence ? "Yes" : "No"}`,
            `Stealth: ${profile.stealth ? "Yes" : "No"}`
          ]
        : [];

      const findingsLines = findings.length
        ? findings.slice(0, 6).flatMap((f) => {
            const sev = safeStr(f.severity, "info").toUpperCase();
            const desc = safeStr(f.description || f, "");
            const one = `[${sev}] ${desc}`;
            return split(one, innerW, S.small, FONT.base, "normal");
          })
        : [];

      const assessment = file.riskExposure && file.riskExposure !== "unknown" ? String(file.riskExposure) : "";
      const assessmentLines = assessment ? split(assessment, innerW, S.small, FONT.base, "normal") : [];

      const shaLines = sha ? split(`SHA256: ${sha}`, innerW, 7, FONT.mono, "normal") : [];

      // Base height: title + meta rows + optional blocks
      let h =
        8 +                               // top padding + title baseline
        nameLines.length * lhB +          // name
        6 +                               // spacing
        3 * lhS +                         // score/size/type rows
        (flagLines.length * lineHeight(8)) +
        (shaLines.length ? (shaLines.length * lineHeight(7) + 2) : 0) +
        (profileLines.length ? (profileLines.length * lhS + 6) : 0) +
        (findingsLines.length ? (findingsLines.length * lhS + 6) : 0) +
        (assessmentLines.length ? (assessmentLines.length * lhS + 6) : 0) +
        S.pad * 2;

      h = Math.min(Math.max(h, 34), 155);

      ensureSpace(h + 8);
      card(h, COLORS.panel);

      // left content
      const x = contentLeft + S.pad;
      let yy = y + 8;

      // Title (file name)
      setFont(FONT.base, "bold", 10);
      setText(COLORS.text);
      doc.text(nameLines, x, yy);
      yy += nameLines.length * lhB + 2;

      // badges right
      const badgeY = y + 10;
      let bx = contentRight - 4;
      // draw from right to left
      const drawBadgeRight = (t, rgb) => {
        setFont(FONT.base, "bold", 7);
        const w = doc.getTextWidth(t) + 4.8;
        bx -= w;
        badge(t, bx, badgeY, rgb);
        bx -= 2;
      };

      drawBadgeRight(level.toUpperCase(), tc);
      if (hasSandbox) drawBadgeRight("SANDBOX", COLORS.purple);

      // Meta rows
      yy = kvRow("Score", safeStr(file.threatScore || 0, "0") + "/100", x, yy, innerW);
      yy = kvRow("Size", safeStr(formatBytes(file.size), "N/A"), x, yy, innerW);
      yy = kvRow("Type", typeText.replace("Type: ", ""), x, yy, innerW);

      // Flags line
      yy += 1;
      setFont(FONT.base, "normal", 8);
      setText(COLORS.muted);
      doc.text("Flags:", x, yy);
      const fl = split(flagLine, innerW - 18, 8, FONT.base, "normal");
      setText(COLORS.text);
      doc.text(fl, x + 18, yy);
      yy += fl.length * lineHeight(8) + 2;

      // SHA
      if (shaLines.length) {
        setFont(FONT.mono, "normal", 7);
        setText(COLORS.faint);
        doc.text(shaLines, x, yy);
        yy += shaLines.length * lineHeight(7) + 2;
      }

      // Profile
      if (profileLines.length) {
        setFont(FONT.base, "bold", 9);
        setText(COLORS.primary);
        doc.text("Behavior Profile", x, yy);
        yy += 4;

        setFont(FONT.base, "normal", 8);
        setText(COLORS.muted);
        profileLines.forEach((t) => {
          doc.text(`• ${t}`, x, yy);
          yy += lhS;
        });
        yy += 2;
      }

      // Findings (up to 6, wrapped)
      if (findingsLines.length) {
        setFont(FONT.base, "bold", 9);
        setText(COLORS.primary);
        doc.text("Key Findings", x, yy);
        yy += 4;

        setFont(FONT.base, "normal", 8);
        setText(COLORS.muted);
        doc.text(findingsLines, x, yy);
        yy += findingsLines.length * lhS + 2;
      }

      // Assessment summary
      if (assessmentLines.length) {
        setFont(FONT.base, "bold", 9);
        setText(COLORS.primary);
        doc.text("Assessment", x, yy);
        yy += 4;

        setFont(FONT.base, "normal", 8);
        setText(COLORS.muted);
        doc.text(assessmentLines.slice(0, 10), x, yy);
      }

      y += h + 8;
    });
  }

  //  URL ANALYSIS 
  doc.addPage();
  drawHeader();
  y = M.top + M.headerH + 6;
  sectionTitle("URL Security Analysis");

  if (urlData.length === 0) {
    const h = 22;
    card(h);
    setFont(FONT.base, "bold", 10);
    setText(COLORS.muted);
    doc.text("No URLs were scanned during this session.", contentLeft + S.pad, y + 11);
    y += h + 8;
  } else {
    urlData.forEach((u, idx) => {
      const level = safeStr(u.threat_level || u.threatLevel, "unknown");
      const tc = threatColor(level);
      const isDeep = !!(u.deep_scan || u.deepScan);

      const urlTxt = safeStr(u.url, "");
      const domainTxt = safeStr(u.domain, "N/A");
      const scoreTxt = safeStr(u.threat_score || u.threatScore || 0, 0);

      const services = u.services || {};
      const findings = Array.isArray(u.findings) ? u.findings : [];

      const innerW = contentWidth - S.pad * 2;
      const lhS = lineHeight(S.small);

      const urlLines = split(`${idx + 1}. ${urlTxt}`, innerW - 50, 9, FONT.base, "bold");

      const svcLines = [];
      if (services.google_safe_browsing?.available) {
        const g = services.google_safe_browsing;
        svcLines.push(`Google Safe Browsing: ${g.threat_found ? `THREAT (${g.threat_type})` : "Safe"}`);
      }
      if (services.urlhaus?.available) {
        const h = services.urlhaus;
        svcLines.push(`URLHaus: ${h.listed ? `LISTED (${h.threat || "Malware"})` : "Not Listed"}`);
      }
      if (services.virustotal_url?.available) {
        const v = services.virustotal_url;
        svcLines.push(`VirusTotal: ${(v.malicious || 0)}/${v.total || 70} flagged`);
      }

      const indLines = findings.length
        ? findings.slice(0, 4).flatMap((f) => split(`• ${safeStr(f.description, "")}`, innerW, 8, FONT.base, "normal"))
        : [];

      // height calc
      let h =
        S.pad * 2 +
        urlLines.length * lhS +
        18 +
        (svcLines.length ? (svcLines.length * lhS + 6) : 0) +
        (indLines.length ? (indLines.length * lhS + 6) : 0);

      h = Math.min(Math.max(h, 34), 140);

      ensureSpace(h + 8);
      card(h, COLORS.panel);

      const x = contentLeft + S.pad;
      let yy = y + 8;

      // URL title
      setFont(FONT.base, "bold", 9);
      setText(COLORS.text);
      doc.text(urlLines, x, yy);
      yy += urlLines.length * lhS + 2;

      // badges
      const badgeY = y + 10;
      let bx = contentRight - 4;
      const drawBadgeRight = (t, rgb) => {
        setFont(FONT.base, "bold", 7);
        const w = doc.getTextWidth(t) + 4.8;
        bx -= w;
        badge(t, bx, badgeY, rgb);
        bx -= 2;
      };
      drawBadgeRight(level.toUpperCase(), tc);
      if (isDeep) drawBadgeRight("DEEP SCAN", COLORS.purple);

      // meta row
      yy = kvRow("Domain", domainTxt, x, yy, innerW);
      yy = kvRow("Score", `${scoreTxt}/100`, x, yy, innerW);

      // services summary
      if (svcLines.length) {
        yy += 2;
        setFont(FONT.base, "bold", 9);
        setText(COLORS.primary);
        doc.text("Threat Intelligence", x, yy);
        yy += 4;

        setFont(FONT.base, "normal", 8);
        setText(COLORS.muted);
        doc.text(svcLines, x, yy);
        yy += svcLines.length * lhS + 2;
      }

      // indicators
      if (indLines.length) {
        yy += 2;
        setFont(FONT.base, "bold", 9);
        setText(COLORS.primary);
        doc.text("Indicators", x, yy);
        yy += 4;

        setFont(FONT.base, "normal", 8);
        setText(COLORS.muted);
        doc.text(indLines, x, yy);
      }

      y += h + 8;
    });
  }

  //  RECOMMENDATIONS 
  doc.addPage();
  drawHeader();
  y = M.top + M.headerH + 6;
  sectionTitle("Recommendations");

  const recommendations = generateRecommendations(fileData, urlData);
  if (!recommendations || !recommendations.length) {
    const h = 18;
    card(h);
    setFont(FONT.base, "normal", 9);
    setText(COLORS.muted);
    doc.text("No recommendations available.", contentLeft + S.pad, y + 10);
    y += h + 8;
  } else {
    recommendations.forEach((rec, i) => {
      const title = safeStr(rec.title, `Recommendation ${i + 1}`);
      const desc = safeStr(rec.description, "");

      const innerW = contentWidth - S.pad * 2;
      const titleLines = split(`${i + 1}. ${title}`, innerW, 10, FONT.base, "bold");
      const descLines = split(desc, innerW, 8, FONT.base, "normal");

      let h = S.pad * 2 + titleLines.length * lineHeight(10) + descLines.length * lineHeight(8) + 8;
      h = Math.min(Math.max(h, 24), 140);

      ensureSpace(h + 6);
      card(h, COLORS.panel);

      const x = contentLeft + S.pad;
      let yy = y + 8;

      setFont(FONT.base, "bold", 10);
      setText(COLORS.primary);
      doc.text(titleLines, x, yy);
      yy += titleLines.length * lineHeight(10) + 2;

      setFont(FONT.base, "normal", 8);
      setText(COLORS.muted);
      doc.text(descLines, x, yy);

      y += h + 6;
    });
  }

  // Footer on every page
  drawFooterAllPages();

  doc.save(`zerorisk-report-${formatTimestamp()}.pdf`);
}


//  HELPER FUNCTIONS 

function calculateFileBoxHeight(file) {
  let height = 28;
  
  if (file.hashes && file.hashes.sha256) height += 5;
  if (file.sandbox_data) height += 5;
  if (file.spywareProfile) height += 20;
  if (file.findings && file.findings.length > 0) height += 16;
  if (file.riskExposure && file.riskExposure !== "unknown") height += 8;
  
  return Math.min(height, 95);
}

function generateRiskAssessmentText(fileData, urlData) {
  const chartData = calculateReportChartData();
  const urlStats = calculateURLStats();
  
  let text = "";
  
  if (fileData.length === 0 && urlData.length === 0) {
    return "No scan data available. Please perform file or URL scans to generate a security assessment.";
  }
  
  if (fileData.length > 0) {
    text += `File Analysis: ${fileData.length} file(s) scanned. `;
    text += `Security Score: ${chartData.avgScore}/100. `;
    
    if (chartData.sandboxCount > 0) {
      text += `${chartData.sandboxCount} file(s) analyzed with sandbox execution. `;
    }
    
    if (chartData.critical > 0) {
      text += `CRITICAL: ${chartData.critical} file(s) require immediate attention. `;
    } else if (chartData.warning > 0) {
      text += `${chartData.warning} file(s) show suspicious patterns. `;
    } else {
      text += "All files appear safe. ";
    }
  }
  
  if (urlData.length > 0) {
    if (text) text += " ";
    text += `URL Analysis: ${urlData.length} URL(s) scanned. `;
    
    if (urlStats.deepScan > 0) {
      text += `${urlStats.deepScan} URL(s) analyzed with Deep Scan sandboxing. `;
    }
    
    if (urlStats.critical > 0) {
      text += `WARNING: ${urlStats.critical} malicious URL(s) detected. Avoid these sites. `;
    } else if (urlStats.warning > 0) {
      text += `${urlStats.warning} URL(s) show suspicious indicators. `;
    } else {
      text += "All URLs appear safe. ";
    }
  }
  
  return text;
}

function generateRecommendations(fileData, urlData) {
  const recs = [];
  const chartData = calculateReportChartData();
  const urlStats = calculateURLStats();
  
  const hasCriticalFiles = chartData.critical > 0;
  const hasCriticalURLs = urlStats.critical > 0;
  
  if (hasCriticalFiles || hasCriticalURLs) {
    recs.push({
      title: "Immediate Action Required",
      description: `Critical threats detected (${chartData.critical} files, ${urlStats.critical} URLs). Quarantine affected files immediately and avoid flagged URLs. Perform full system scan.`
    });
  }
  
  if (fileData.length > 0) {
    const hasKeyloggers = fileData.some(f => f.keyloggerDetected);
    const hasSpoofing = fileData.some(f => f.extensionMismatch);
    const hasSandbox = chartData.sandboxCount > 0;
    
    if (hasKeyloggers) {
      recs.push({
        title: "Credential Security Alert",
        description: "Keylogger signatures detected. Change all passwords from a clean device, enable 2FA, and check for unauthorized account access."
      });
    }
    
    if (hasSpoofing) {
      recs.push({
        title: "Extension Spoofing Detected",
        description: "Files with misleading extensions found. Always verify actual file types before opening. Enable 'Show file extensions' in your OS settings."
      });
    }
    
    if (hasSandbox) {
      recs.push({
        title: "Sandbox Analysis Complete",
        description: `${chartData.sandboxCount} file(s) were analyzed using real-time sandbox execution. Review process activity and network connections for additional context.`
      });
    }
    
    if (chartData.warning > 0 && !hasCriticalFiles) {
      recs.push({
        title: "Review Warning Files",
        description: `${chartData.warning} file(s) show suspicious patterns. Review individually and consider sandbox analysis before use.`
      });
    }
    
    recs.push({
      title: "Enable Real-time Protection",
      description: "Use antivirus with real-time scanning and behavioral analysis to catch threats before execution."
    });
  }
  
  if (urlData.length > 0) {
    if (urlStats.critical > 0 || urlStats.high > 0) {
      recs.push({
        title: "Avoid Malicious Websites",
        description: "Multiple dangerous URLs detected. Do not visit these sites. Clear browser cache and check for unauthorized redirects."
      });
    }
    
    if (urlStats.deepScan > 0) {
      recs.push({
        title: "Deep Scan Analysis Complete",
        description: `${urlStats.deepScan} URL(s) were analyzed using live browser sandboxing. Review screenshots and network activity for additional context.`
      });
    }
    
    const hasLocalOnly = urlStats.localBased > 0;
    if (hasLocalOnly) {
      recs.push({
        title: "Backend Analysis Unavailable",
        description: "Some URLs used local heuristic analysis only. Re-scan when backend is online for complete threat intelligence."
      });
    }
    
    recs.push({
      title: "Browser Security",
      description: "Keep browsers updated, use HTTPS-Everywhere, and install security extensions to block phishing and malware sites."
    });
  }
  
  recs.push({
    title: "Regular Security Scanning",
    description: "Schedule weekly scans of downloads and system directories. Maintain updated threat signatures."
  });
  
  recs.push({
    title: "Backup Strategy",
    description: "Maintain offline backups of critical data. Use 3-2-1 rule: 3 copies, 2 different media, 1 offsite."
  });
  
  return recs;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatTimestamp() {
  const now = new Date();
  return now.getFullYear() + 
         String(now.getMonth() + 1).padStart(2, "0") + 
         String(now.getDate()).padStart(2, "0") + "_" +
         String(now.getHours()).padStart(2, "0") +
         String(now.getMinutes()).padStart(2, "0");
}

function generateReportId() {
  return "ZRS-" + Math.random().toString(36).substring(2, 10).toUpperCase();
}

//  NOTIFICATION 

function showNotification(message, type = "info") {
  const existing = document.querySelectorAll(".zerorisk-notification");
  existing.forEach(n => n.remove());

  const notification = document.createElement("div");
  notification.className = "zerorisk-notification fixed top-20 right-4 z-50 px-6 py-4 rounded-lg shadow-2xl font-medium text-sm transition-all duration-300";
  
  const colors = {
    success: "bg-green-500/90 text-white border border-green-400",
    error: "bg-red-500/90 text-white border border-red-400",
    warning: "bg-yellow-500/90 text-black border border-yellow-400",
    info: "bg-blue-500/90 text-white border border-blue-400"
  };
  
  notification.className += " " + (colors[type] || colors.info);
  notification.innerHTML = `
    <div class="flex items-center gap-3">
      <span>${type === "success" ? "✓" : type === "error" ? "✗" : type === "warning" ? "⚠" : "ℹ"}</span>
      <span>${message}</span>
    </div>
  `;
  
  document.body.appendChild(notification);
  
  // Animate in
  requestAnimationFrame(() => {
    notification.style.transform = "translateX(0)";
    notification.style.opacity = "1";
  });
  
  // Remove after delay
  setTimeout(() => {
    notification.style.transform = "translateX(100%)";
    notification.style.opacity = "0";
    setTimeout(() => notification.remove(), 300);
  }, 4000);
}
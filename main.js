function generateRiskExplanation(analysis) {
  const level = analysis.threatLevel;
  const score = analysis.threatScore;
  const p = analysis.spywareProfile;
  const findings = analysis.findings;
  const vt = analysis.virustotal;
  const entropy = analysis.entropy;

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  
  // Check for specific merged indicators
  const hasVirusTotal = vt && vt.found && vt.malicious > 0;
  const vtCount = hasVirusTotal ? vt.malicious : 0;
  const hasHighEntropy = entropy > 7.5;
  const hasYARA = findings.some(f => f.type === 'yara_match' || f.rule);
  const yaraRules = findings.filter(f => f.type === 'yara_match' || f.rule).map(f => f.rule || f.type);
  const hasKeyloggerYARA = yaraRules.some(r => r && r.toLowerCase().includes('keylogger'));
  
  // Check for sandbox findings
  const hasSandboxFindings = analysis.sandbox_data && analysis.sandbox_data.findings && analysis.sandbox_data.findings.length > 0;
  const sandboxCritical = hasSandboxFindings ? analysis.sandbox_data.findings.filter(f => f.severity === 'critical').length : 0;
  const sandboxMalicious = analysis.sandbox_data && analysis.sandbox_data.verdict === 'malicious';

  // CRITICAL LEVEL
  if (level === 'critical') {
    if (sandboxMalicious) {
      return `CRITICAL: Sandbox analysis confirmed MALICIOUS behavior during execution. Immediate quarantine recommended.`;
    }
    if (hasVirusTotal && vtCount >= 5) {
      return `CRITICAL: ${vtCount} antivirus engines confirm this is known malware. Immediate quarantine recommended.`;
    }
    if (hasVirusTotal) {
      return `CRITICAL: VirusTotal flagged by ${vtCount} engines + ${criticalCount} critical local indicators. Verified threat.`;
    }
    if (p.surveillance && p.credentialHarvesting) {
      return `CRITICAL: Active surveillance with credential harvesting. ${criticalCount} critical indicators detected.`;
    }
    if (hasKeyloggerYARA) {
      return `CRITICAL: Keylogger confirmed by YARA rule + ${criticalCount} critical indicators. Input capture capability verified.`;
    }
    if (criticalCount > 0) {
      return `CRITICAL: ${criticalCount} critical threat indicators. File exhibits malicious behavior patterns.`;
    }
    return `CRITICAL: Threat score ${score}/100 exceeds safety thresholds. Multiple coordinated suspicious behaviors.`;
  }

  // HIGH LEVEL
  if (level === 'high') {
    if (hasSandboxFindings && sandboxCritical > 0) {
      return `HIGH RISK: Sandbox detected ${sandboxCritical} critical behavior(s) during execution. Suspicious activity confirmed.`;
    }
    if (hasVirusTotal) {
      return `HIGH RISK: VirusTotal shows ${vtCount} detections. Known suspicious file with confirmed indicators.`;
    }
    if (hasHighEntropy && hasYARA) {
      return `HIGH RISK: Packed/encrypted file with ${highCount} YARA matches. Attempting to evade detection.`;
    }
    if (p.surveillance) {
      return `HIGH RISK: Surveillance indicators present. Monitoring capability detected in code.`;
    }
    if (p.stealth) {
      return `HIGH RISK: Deception techniques (extension spoofing). Trying to appear as different file type.`;
    }
    if (hasYARA) {
      return `HIGH RISK: ${yaraRules.length} YARA rule(s) matched: ${yaraRules.slice(0, 2).join(', ')}. Known malware signatures.`;
    }
    if (highCount > 0) {
      return `HIGH RISK: ${highCount} high-confidence threat signals. Code execution capabilities present.`;
    }
    return `HIGH RISK: Combined threat indicators exceed safety threshold (score: ${score}/100).`;
  }

  // MEDIUM LEVEL
  if (level === 'medium') {
    if (hasHighEntropy) {
      return `MODERATE RISK: High entropy (${entropy}/8) suggests packing/encryption. Possibly hiding code.`;
    }
    if (hasYARA) {
      return `MODERATE RISK: YARA match: ${yaraRules[0]}. Known suspicious pattern detected.`;
    }
    if (mediumCount > 0) {
      return `MODERATE RISK: ${mediumCount} suspicious indicators. Some patterns warrant additional scrutiny.`;
    }
    if (p.dataExfiltration) {
      return `MODERATE RISK: Network communication capability. Could transmit data externally.`;
    }
    return `MODERATE RISK: Low-confidence threat indicators (score: ${score}/100).`;
  }

  // LOW LEVEL - NOW INCLUDES YARA INFO!
  if (level === 'low') {
    if (hasKeyloggerYARA) {
      return `LOW RISK: Keylogger pattern detected (${yaraRules[0]}) but low confidence score. Monitor file behavior closely.`;
    }
    if (hasYARA) {
      return `LOW RISK: YARA matched but low severity. Pattern: ${yaraRules[0]}. Monitor for changes.`;
    }
    if (entropy > 6.5) {
      return `LOW RISK: Slightly elevated entropy (${entropy}). Minor compression detected.`;
    }
    return `LOW RISK: Minor anomalies detected. File appears largely safe with minimal irregularities.`;
  }

  // SAFE
  return `SAFE: No threats detected. Clean file hash, normal entropy, no suspicious patterns.`;
}
const BACKEND_URL = 'https://zerorisk-sentinel-backend.onrender.com';

// Deep scan polling configuration
const SANDBOX_POLL_CONFIG = {
  maxAttempts: 30,
  interval: 2000,
  timeout: 60000
};

class RealFileScanner {
  constructor() {
    this.backendUrl = BACKEND_URL;
  }

  async scanFile(file, deepScan = false) {
    // If deep scan enabled, use deep scan endpoint
    if (deepScan) {
      return this.scanFileDeep(file);
    }
    return this.scanFileNormal(file);
  }

  async scanFileNormal(file) {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${this.backendUrl}/api/scan-file`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Scan failed');
      }

      return this.transformBackendResult(result.data, file);

    } catch (error) {
      console.error('[SCAN ERROR]', error);
      return null;
    }
  }

  async scanFileDeep(file, onProgress = null) {
    const formData = new FormData();
    formData.append('file', file);

    try {
      // Step 1: Submit for deep scan (regular + sandbox)
      if (onProgress) onProgress(10, 'Submitting to sandbox...');
      
      const response = await fetch(`${this.backendUrl}/api/scan-file-deep`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Deep scan failed');
      }

      // Get regular scan results immediately
      const regularResult = result.regular_scan;
      const sandboxSubmit = result.sandbox;

      // If sandbox submission failed, return regular results only
      if (!sandboxSubmit || !sandboxSubmit.success) {
        console.warn('[DEEP SCAN] Sandbox submission failed, using regular scan only');
        const analysis = this.transformBackendResult(regularResult, file);
        analysis.deep_scan = false;  // FIX: Don't show deep scan badge if sandbox failed
        analysis.deep_scan_attempted = true;  // But track that we tried
        analysis.sandbox_error = sandboxSubmit?.error || 'Sandbox submission failed - API key not configured';
        return analysis;
      }

      // Step 2: Poll for sandbox results
      const jobId = sandboxSubmit.job_id;
      if (onProgress) onProgress(20, 'Sandbox analyzing... (wait 30-60s)');

      const sandboxResult = await this.pollSandboxResult(jobId, onProgress);

      // Merge regular and sandbox results
      const mergedResult = this.mergeSandboxResults(regularResult, sandboxResult, file);
      return mergedResult;

    } catch (error) {
      console.error('[DEEP SCAN ERROR]', error);
      // Fallback to normal scan
      return this.scanFileNormal(file);
    }
  }

  async pollSandboxResult(jobId, onProgress = null) {
    for (let attempt = 0; attempt < SANDBOX_POLL_CONFIG.maxAttempts; attempt++) {
      const progress = 20 + Math.round((attempt / SANDBOX_POLL_CONFIG.maxAttempts) * 75);
      if (onProgress) onProgress(progress, `Analyzing... (${attempt + 1}/${SANDBOX_POLL_CONFIG.maxAttempts})`);

      await new Promise(r => setTimeout(r, SANDBOX_POLL_CONFIG.interval));

      try {
        const response = await fetch(`${this.backendUrl}/api/sandbox/result/${jobId}`);
        const result = await response.json();

        if (result.success && result.status === 'completed') {
          return result;
        }

        if (result.status === 'failed') {
          throw new Error(result.error || 'Sandbox analysis failed');
        }

      } catch (e) {
        console.warn(`[SANDBOX POLL] Attempt ${attempt + 1} failed:`, e.message);
      }
    }

    throw new Error('Sandbox analysis timeout');
  }

  mergeSandboxResults(regularResult, sandboxResult, file) {
    // Start with regular scan result
    const merged = this.transformBackendResult(regularResult, file);
    
    // Add deep scan flag
    merged.deep_scan = true;
    
    // If sandbox result exists, merge its data
    if (sandboxResult && sandboxResult.success) {
      merged.sandbox_data = sandboxResult.sandbox_data || {};
      
      // Merge findings from sandbox
      if (sandboxResult.findings && sandboxResult.findings.length > 0) {
        // Add sandbox findings with prefix
        const sandboxFindings = sandboxResult.findings.map(f => ({
          ...f,
          source: 'sandbox',
          description: f.description
        }));
        merged.findings = [...merged.findings, ...sandboxFindings];
      }
      
      // Take the higher threat score
      if (sandboxResult.threat_score > merged.threatScore) {
        merged.threatScore = sandboxResult.threat_score;
        merged.threatLevel = sandboxResult.threat_level;
      }
      
      // Update explanation with sandbox info
      if (sandboxResult.explanation) {
        merged.sandboxExplanation = sandboxResult.explanation;
      }
    }

    return merged;
  }

  transformBackendResult(backendData, originalFile) {
    const findings = backendData.findings || [];
    
    const formattedFindings = findings.map(f => ({
      type: f.type,
      severity: f.severity,
      description: f.description || `YARA rule: ${f.rule}`,
      rule: f.rule || null,
      tags: f.tags || [],
      source: f.source || 'regular'
    }));

    if (backendData.entropy > 7.5) {
      formattedFindings.push({
        type: 'high_entropy',
        severity: 'medium',
        description: `High entropy detected (${backendData.entropy}/8.0) - file may be packed or encrypted`,
        source: 'regular'
      });
    }

    if (backendData.virustotal && backendData.virustotal.found) {
      const vt = backendData.virustotal;
      formattedFindings.unshift({
        type: 'virustotal',
        severity: vt.malicious >= 5 ? 'critical' : vt.malicious >= 2 ? 'high' : 'medium',
        description: `VirusTotal: ${vt.malicious}/${vt.total} engines detected this file as malicious`,
        source: 'regular'
      });
    }

    return {
      name: backendData.filename,
      size: backendData.size,
      type: originalFile.type,
      lastModified: originalFile.lastModified,
      isAPK: originalFile.name.toLowerCase().endsWith('.apk'),
      threatLevel: backendData.threat_level,
      threatScore: backendData.threat_score,
      findings: formattedFindings,
      fileHeader: backendData.hashes?.sha256?.substring(0, 16) || 'N/A',
      extensionMismatch: findings.some(f => f.type === 'extension_mismatch'),
      riskExposure: this.generateRiskExplanation(backendData),
      malwareDetected: backendData.threat_level === 'critical' || backendData.threat_level === 'high',
      keyloggerDetected: findings.some(f => f.rule && f.rule.toLowerCase().includes('keylogger')),
      hashes: backendData.hashes,
      entropy: backendData.entropy,
      fileType: backendData.file_type,
      virustotal: backendData.virustotal,
      deep_scan: backendData.deep_scan || false,
      sandbox_data: backendData.sandbox_data || null,
      sandboxExplanation: backendData.explanation || null,
      spywareProfile: {
        surveillance: findings.some(f => f.rule && f.rule.toLowerCase().includes('keylogger')),
        dataExfiltration: findings.some(f => f.description && f.description.toLowerCase().includes('network')),
        persistence: findings.some(f => f.rule && f.rule.toLowerCase().includes('persistence')),
        stealth: backendData.entropy > 7.5 || findings.some(f => f.type === 'extension_mismatch'),
        credentialHarvesting: findings.some(f => f.rule && f.rule.toLowerCase().includes('keylogger')),
        confidenceScore: backendData.threat_score
      }
    };
  }

  generateRiskExplanation(backendData) {
    const findings = backendData.findings || [];
    const vt = backendData.virustotal;
    
    let explanations = [];

    const yaraMatches = findings.filter(f => f.type === 'yara_match');
    if (yaraMatches.length > 0) {
      explanations.push(`${yaraMatches.length} YARA rule(s) matched`);
    }

    if (vt && vt.found && vt.malicious > 0) {
      explanations.push(`${vt.malicious} antivirus engines flagged this file`);
    }

    if (backendData.entropy > 7.5) {
      explanations.push('High entropy suggests packing/encryption');
    }

    if (findings.some(f => f.type === 'extension_mismatch')) {
      explanations.push('File extension does not match actual file type');
    }

    if (explanations.length === 0) {
      return 'No significant threats detected';
    }

    return explanations.join('; ');
  }
}

class CyberGuardSpywareAnalyzer {
  constructor() {
    this.files = [];
    this.backendAvailable = false;
    this.checkBackendStatus();
    this.analysisResults = new Map();
    this.signatureDatabase = this.initializeSignatureDatabase();
    this.fileHeaders = this.initializeFileHeaders();
    this.realScanner = new RealFileScanner();
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.initializeAnimations();
    this.startMatrixBackground();
    this.updateStats();
  }
  
  async checkBackendStatus() {
    try {
      const res = await fetch("https://zerorisk-sentinel-backend.onrender.com/api/status");
      if (res.ok) {
        const data = await res.json();
        this.backendAvailable = true;

        // Update UI status
        const statusDot = document.getElementById('backendStatusDot');
        const statusText = document.getElementById('backendStatusText');

        if (data.file_scanner?.available) {
          if (data.file_scanner?.yara_loaded) {
            if (statusDot) statusDot.className = 'w-2 h-2 rounded-full bg-green-400';
            if (statusText) statusText.textContent = 'Backend Active (Better scanning)';
          } else {
            if (statusDot) statusDot.className = 'w-2 h-2 rounded-full bg-yellow-400';
            if (statusText) statusText.textContent = 'Backend Online';
          }
        }

        console.log("[BACKEND] File scanner online", data);
      }
    } catch (e) {
      this.backendAvailable = false;
      const statusDot = document.getElementById('backendStatusDot');
      const statusText = document.getElementById('backendStatusText');
      if (statusDot) statusDot.className = 'w-2 h-2 rounded-full bg-red-400';
      if (statusText) statusText.textContent = 'Backend Offline (Local Mode)';
      console.warn("[BACKEND] File scanner offline");
    }
  }

  // File signature database for malware detection
  initializeSignatureDatabase() {
    return {
      // Known malware signatures (simplified patterns for demonstration)
      malware: [
        {
          pattern: /eval\s*\(/,
          threat: "high",
          description: "Code execution detected",
        },
        {
          pattern: /shell\s*\(/,
          threat: "high",
          description: "Shell command execution",
        },
        {
          pattern: /system\s*\(/,
          threat: "high",
          description: "System command execution",
        },
        {
          pattern: /exec\s*\(/,
          threat: "high",
          description: "Process execution detected",
        },
        {
          pattern: /cmd\.exe/,
          threat: "high",
          description: "Windows command prompt",
        },
        {
          pattern: /powershell\.exe/,
          threat: "high",
          description: "PowerShell execution",
        },
        {
          pattern: /wscript\.shell/,
          threat: "high",
          description: "Windows Script Host",
        },
        {
          pattern: /keylogger/i,
          threat: "critical",
          description: "Keylogging-related patterns observed",
        },
        {
          pattern: /keystroke/i,
          threat: "critical",
          description: "Keystroke logging",
        },
        {
          pattern: /password.*steal/i,
          threat: "critical",
          description: "Password theft",
        },
        { pattern: /trojan/i, threat: "critical", description: "Trojan horse" },
        {
          pattern: /ransomware/i,
          threat: "critical",
          description: "Ransomware detected",
        },
        {
          pattern: /encrypt.*file/i,
          threat: "high",
          description: "File encryption",
        },
        {
          pattern: /delete.*file/i,
          threat: "medium",
          description: "File deletion",
        },
        {
          pattern: /registry.*modify/i,
          threat: "high",
          description: "Registry modification indicators found in file content",
        },
        {
          pattern: /startup.*add/i,
          threat: "high",
          description: "Startup persistence indicators found in file content",
        },
        {
          pattern: /network.*send/i,
          threat: "medium",
          description: "Network-related indicators found in file content",
        },
        {
          pattern: /http.*post/i,
          threat: "medium",
          description: "HTTP data exfiltration",
        },
        {
          pattern: /ftp.*upload/i,
          threat: "high",
          description: "FTP data transfer",
        },
        {
          pattern: /email.*send/i,
          threat: "medium",
          description: "Email data theft",
        },
      ],
      // Suspicious patterns
      suspicious: [
        {
          pattern: /base64_decode/i,
          threat: "medium",
          description: "Base64 decoding",
        },
        {
          pattern: /gzinflate/i,
          threat: "medium",
          description: "Compression detected",
        },
        {
          pattern: /str_rot13/i,
          threat: "low",
          description: "String obfuscation",
        },
        {
          pattern: /chr\s*\(/,
          threat: "low",
          description: "Character encoding",
        },
        {
          pattern: /fromCharCode/i,
          threat: "low",
          description: "Character encoding",
        },
        {
          pattern: /charCodeAt/i,
          threat: "low",
          description: "Character analysis",
        },
        {
          pattern: /substr/i,
          threat: "low",
          description: "String manipulation",
        },
        {
          pattern: /substring/i,
          threat: "low",
          description: "String manipulation",
        },
        {
          pattern: /replace.*regex/i,
          threat: "medium",
          description: "String replacement",
        },
        {
          pattern: /split.*join/i,
          threat: "low",
          description: "String manipulation",
        },
      ],
    };
  }

  // File header signatures for type detection
  initializeFileHeaders() {
    return {
      JPEG: ["FFD8FFE0", "FFD8FFE1", "FFD8FFE2", "FFD8FFE3", "FFD8FFE8"],
      PNG: ["89504E47"],
      GIF: ["47494638"],
      BMP: ["424D"],
      TIFF: ["49492A00", "4D4D002A"],
      PDF: ["25504446"],
      ZIP: ["504B0304", "504B0506", "504B0708"],
      RAR: ["52617221"],
      "7Z": ["377ABCAF271C"],
      TAR: ["7573746172"],
      GZ: ["1F8B"],
      EXE: ["4D5A"],
      DLL: ["4D5A"],
      MSI: ["D0CF11E0A1B11AE1"],
      DOC: ["D0CF11E0A1B11AE1"],
      XLS: ["D0CF11E0A1B11AE1"],
      PPT: ["D0CF11E0A1B11AE1"],
      DOCX: ["504B030414000600"],
      XLSX: ["504B030414000600"],
      PPTX: ["504B030414000600"],
      MP3: ["494433", "FFFB", "FFF3", "FFFA"],
      MP4: ["0000001866747970", "0000001C66747970"],
      AVI: ["52494646"],
      WMV: ["3026B2758E66CF11"],
      MOV: ["0000001466747970"],
      ISO: ["4344303031"],
      MPG: ["000001BA", "000001B3"],
      FLV: ["464C56"],
      SWF: ["465753", "435753"],
      JAR: ["504B0304"],
      APK: ["504B0304"],
      CLASS: ["CAFEBABE"],
      PSD: ["38425053"],
      AI: ["25504446"],
      EPS: ["25215053"],
      PS: ["25215053"],
      RTF: ["7B5C72746631"],
      XML: ["3C3F786D6C"],
      HTML: ["3C21444F4354595045", "3C68746D6C"],
      JS: ["2F2A", "2F2F"],
      CSS: ["2F2A", "4063686172736574"],
      PHP: ["3C3F706870"],
      SQL: ["2D2D", "2F2A"],
      BAT: ["406563686F20", "4063686F20"],
      CMD: ["406563686F20", "4063686F20"],
      PS1: ["2323"],
      VBS: ["2773C61766553"],
      WSF: ["3C3F786D6C"],
      TXT: [],
      CSV: [],
      INI: [],
      CFG: [],
      LOG: [],
    };
  }

  setupEventListeners() {
    const dropZone = document.getElementById("fileDropZone");
    const fileInput = document.getElementById("fileInput");

    // Click to select files
    dropZone.addEventListener("click", () => fileInput.click());

    // File input change
    fileInput.addEventListener("change", (e) =>
      this.handleFiles(e.target.files)
    );

    // Drag and drop events
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.classList.add("drag-over");
    });

    dropZone.addEventListener("dragleave", () => {
      dropZone.classList.remove("drag-over");
    });

    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.classList.remove("drag-over");
      this.handleFiles(e.dataTransfer.files);
    });
  }

  async handleFiles(fileList) {
    const files = Array.from(fileList);
    this.files.push(...files);

    // Show scanning progress
    document.getElementById("scanningProgress").classList.remove("hidden");

    // Check if deep scan is enabled
    const deepScanEnabled = sessionStorage.getItem("deepScan") === "on";

    // Process files sequentially
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      await this.analyzeFile(file, i, files.length, deepScanEnabled);
    }

    // Hide progress after completion
    setTimeout(() => {
      document.getElementById("scanningProgress").classList.add("hidden");
    }, 2000);

    this.updateFileQueue();
    this.updateStats();
    
    // STORE RESULTS FOR RESULTS PAGE
    const resultsArray = Array.from(this.analysisResults.values());
    sessionStorage.setItem("analysisResults", JSON.stringify(resultsArray));
    
    if (typeof initializeCharts === 'function') {
      initializeCharts();
    }
    if (typeof renderDynamicResults === 'function') {
      renderDynamicResults(resultsArray);
    }
  }

  async analyzeFile(file, index, total, deepScanEnabled = false) {
    const progressText = document.getElementById("progressText");
    const progressFill = document.getElementById("progressFill");
    const currentFile = document.getElementById("currentFile");

    const updateProgress = (percent, message) => {
      progressText.textContent = `${Math.round(percent)}%`;
      progressFill.style.width = `${percent}%`;
      if (message) currentFile.textContent = message;
    };

    const baseProgress = ((index + 1) / total) * 100;
    updateProgress(baseProgress * 0.1, `Initializing scan for: ${file.name}`);

    // Log analysis start
    this.logToTerminal(`[ANALYZING] ${file.name} (${this.formatBytes(file.size)})`, "blue");
    
    if (deepScanEnabled) {
      this.logToTerminal(`[DEEP SCAN] Sandbox analysis enabled for ${file.name}`, "purple");
    }

    let analysis;
    const isAPK = file.name.toLowerCase().endsWith('.apk');
    
    if (isAPK) {
      // APK: Use specialized Android analysis + sandbox if deep scan enabled
      this.logToTerminal(`[APK] Using specialized Android analysis for ${file.name}`, "blue");
      analysis = await this.performAPKAnalysis(file, deepScanEnabled, updateProgress);
    } else {
      // NON-APK: Try backend first
      if (deepScanEnabled) {
        // Deep scan with sandbox
        analysis = await this.realScanner.scanFile(file, true);
        if (analysis) {
          this.logToTerminal(`[BACKEND] Deep scan complete for ${file.name}`, "green");
        }
      } else {
        // Normal scan
        analysis = await this.realScanner.scanFile(file, false);
      }

      // If backend failed or returned null, fall back to local analysis
      if (!analysis) {
        this.logToTerminal(`[FALLBACK] Using local analysis for ${file.name}`, "yellow");
        analysis = await this.performFileAnalysis(file);
      } else {
        this.logToTerminal(`[BACKEND] Real scan complete for ${file.name}`, "green");
      }
    }
    
    this.analysisResults.set(file.name, analysis);

    // Log results
    this.logAnalysisResults(file.name, analysis);

    // Update threat level
    this.updateThreatLevel();
  }

  async performAPKAnalysis(file, deepScanEnabled, onProgress) {
    const analysis = {
      name: file.name,
      size: file.size,
      type: file.type,
      lastModified: file.lastModified,
      isAPK: true,
      threatLevel: "safe",
      threatScore: 0,
      findings: [],
      fileHeader: null,
      extensionMismatch: false,
      riskExposure: "unknown",
      malwareDetected: false,
      keyloggerDetected: false,
      deep_scan: deepScanEnabled,
      sandbox_data: null,
      spywareProfile: {
        surveillance: false,
        dataExfiltration: false,
        persistence: false,
        stealth: false,
        credentialHarvesting: false,
        confidenceScore: 0,
      },
    };

    const MAX_APK_SIZE = 8 * 1024 * 1024; // 8 MB

    if (file.size > MAX_APK_SIZE) {
      analysis.threatLevel = "low";
      analysis.threatScore = 10;
      analysis.riskExposure = "APK too large for cloud analysis";
      analysis.findings.push({
        type: "apk_size_limit",
        severity: "low",
        description: "APK exceeds cloud upload limits. Full analysis requires local backend.",
      });
      showNotification("APK too large for online analysis. Use local backend for full scan.", "error");
      return analysis;
    }

    try {
      // Step 1: Regular APK analysis
      if (onProgress) onProgress(15, 'Analyzing APK permissions...');
      
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch(
        "https://zerorisk-sentinel-backend.onrender.com/api/analyze-apk",
        {
          method: "POST",
          body: formData,
        }
      );

      const backend = await res.json();

      if (backend.success) {
        const level = backend.data.risk_level || "safe";
      
        analysis.apkAnalysis = {
          backendAvailable: true,
          riskScore: backend.data.risk_score ?? 0,
          riskLevel: level,
          riskyPermissions: backend.data.risky_permissions ?? [],
          explanation: backend.data.explanation || "No explanation available",
          apkMetadata: backend.data.apk_metadata || {},
        };
      
        analysis.threatScore = backend.data.risk_score;
        analysis.threatLevel = backend.data.risk_level;
      
        analysis.hashes = backend.data.hashes || {};
        analysis.entropy = backend.data.entropy || 0;
        analysis.virustotal = backend.data.virustotal || null;
        analysis.file_type = backend.data.file_type || {};
      
        analysis.spywareProfile = {
          surveillance: false,
          dataExfiltration: false,
          persistence: false,
          stealth: false,
          credentialHarvesting: false,
          confidenceScore: 0,
          networkContext: "apk",
        };
        analysis.keyloggerDetected = false;
        analysis.riskExposure = backend.data.explanation || "Permission-based Android analysis";
      
        analysis.findings = [
          {
            type: "apk_backend",
            severity: backend.data.risk_level,
            description: "Deep APK permission analysis completed by Python backend",
          },
          ...(backend.data.findings || [])
        ];
      }

      // Step 2: If deep scan enabled, also run sandbox analysis
      if (deepScanEnabled && this.backendAvailable) {
        if (onProgress) onProgress(40, 'Submitting APK to sandbox...');
        
        try {
          const sandboxFormData = new FormData();
          sandboxFormData.append('file', file);
          
          const sandboxRes = await fetch(`${BACKEND_URL}/api/sandbox/submit`, {
            method: 'POST',
            body: sandboxFormData
          });
          
          const sandboxSubmit = await sandboxRes.json();
          
          if (sandboxSubmit.success) {
            if (onProgress) onProgress(50, 'Sandbox analyzing APK... (wait 30-60s)');
            
            const jobId = sandboxSubmit.job_id;
            const sandboxResult = await this.pollSandboxForAPK(jobId, onProgress);
            
            if (sandboxResult && sandboxResult.success) {
              analysis.sandbox_data = sandboxResult.sandbox_data || {};
              
              // Merge sandbox findings
              if (sandboxResult.findings && sandboxResult.findings.length > 0) {
                analysis.findings.push(...sandboxResult.findings.map(f => ({
                  ...f,
                  source: 'sandbox'
                })));
              }
              
              // Update threat level if sandbox found something worse
              if (sandboxResult.threat_score > analysis.threatScore) {
                analysis.threatScore = sandboxResult.threat_score;
                analysis.threatLevel = sandboxResult.threat_level;
              }
              
              analysis.sandboxExplanation = sandboxResult.explanation;
            }
          }
        } catch (e) {
          console.warn('[APK SANDBOX] Failed:', e);
          analysis.sandbox_error = 'Sandbox analysis failed';
        }
      }

      // Final threat level determination
      const confidenceScore = analysis.spywareProfile?.confidenceScore || 0;
      const finalScore = Math.min(100, Math.max(analysis.threatScore, confidenceScore));

      if (finalScore >= 80) analysis.threatLevel = "critical";
      else if (finalScore >= 60) analysis.threatLevel = "high";
      else if (finalScore >= 30) analysis.threatLevel = "medium";
      else if (finalScore >= 15) analysis.threatLevel = "low";
      else analysis.threatLevel = "safe";

    } catch (error) {
      analysis.findings.push({
        type: "error",
        severity: "low",
        description: `APK analysis error: ${error.message}`,
      });
    }

    analysis.riskExposure = generateRiskExplanation(analysis);
    return analysis;
  }

  async pollSandboxForAPK(jobId, onProgress) {
    for (let attempt = 0; attempt < SANDBOX_POLL_CONFIG.maxAttempts; attempt++) {
      const progress = 50 + Math.round((attempt / SANDBOX_POLL_CONFIG.maxAttempts) * 45);
      if (onProgress) onProgress(progress, `Sandbox analyzing APK... (${attempt + 1}/${SANDBOX_POLL_CONFIG.maxAttempts})`);

      await new Promise(r => setTimeout(r, SANDBOX_POLL_CONFIG.interval));

      try {
        const response = await fetch(`${BACKEND_URL}/api/sandbox/result/${jobId}`);
        const result = await response.json();

        if (result.success && result.status === 'completed') {
          return result;
        }

        if (result.status === 'failed') {
          throw new Error(result.error || 'Sandbox analysis failed');
        }
      } catch (e) {
        console.warn(`[APK SANDBOX POLL] Attempt ${attempt + 1} failed:`, e.message);
      }
    }
    
    throw new Error('Sandbox analysis timeout');
  }

  async performFileAnalysis(file) {
    // ... existing performFileAnalysis code remains exactly the same ...
    const analysis = {
      name: file.name,
      size: file.size,
      type: file.type,
      lastModified: file.lastModified,
      threatLevel: "safe",
      threatScore: 0,
      findings: [],
      fileHeader: null,
      extensionMismatch: false,
      riskExposure: "unknown",
      malwareDetected: false,
      keyloggerDetected: false,
      deep_scan: false,
      sandbox_data: null,
      spywareProfile: {
        surveillance: false,
        dataExfiltration: false,
        persistence: false,
        stealth: false,
        credentialHarvesting: false,
        confidenceScore: 0,
      },
    };

    try {
      // Read file header (first 32 bytes)
      const header = await this.readFileHeader(file);
      analysis.fileHeader = header;

      // Check file type based on header
      const detectedType = this.detectFileType(header);
      const extensionUpper = file.name.split(".").pop().toUpperCase();
      const isAPK =
        extensionUpper === "APK" ||
        detectedType === "APK" ||
        (detectedType === "ZIP" && extensionUpper === "APK");
      analysis.isAPK = isAPK;

      let extension = file.name.split(".").pop().toUpperCase();

      // Normalize common equivalent extensions
      const extensionAliases = {
        JPG: "JPEG",
        JPEG: "JPEG",
        HTM: "HTML",
      };

      if (extensionAliases[extension]) {
        extension = extensionAliases[extension];
      }

      // Check for extension mismatch
      if (
        detectedType &&
        detectedType !== extension &&
        detectedType !== "UNKNOWN" &&
        !(detectedType === "ZIP" && extension === "APK")
      ) {
        analysis.spywareProfile.stealth = true;
        analysis.extensionMismatch = true;
        analysis.findings.push({
          type: "extension_mismatch",
          severity: "high",
          description: `File appears to be ${detectedType} but has .${extension} extension`,
        });
        analysis.threatScore += 30;
      }

      // Check for RTL Override spoofing
      if (this.checkRTLOSpoofing(file.name)) {
        analysis.spywareProfile.stealth = true;
        analysis.findings.push({
          type: "rlo_spoofing",
          severity: "critical",
          description:
            "Right-to-Left Override character detected - potential extension spoofing",
        });
        analysis.threatScore += 50;
      }
      
      // JS-specific heuristic checks (static analysis)
      const extensionLower = file.name.split(".").pop().toLowerCase();
      const isJavaScript = extensionLower === "js";
      const isHtmlOrCss = ["html", "htm", "css"].includes(extensionLower);
      
      // Scan for malware signatures
      let content = "";
      let malwareFindings = [];

      content = await this.readFileContent(file);
      malwareFindings = this.scanForMalware(content);
      analysis.findings.push(...malwareFindings);

      if (isJavaScript) {
        const jsDangerPatterns = [
          /eval\s*\(/i,
          /Function\s*\(/i,
          /atob\s*\(/i,
          /fromCharCode/i,
          /document\.cookie/i,
          /localStorage/i,
          /fetch\s*\(/i,
          /XMLHttpRequest/i,
        ];
        if (jsDangerPatterns.some((p) => p.test(content))) {
          analysis.findings.push({
            type: "js_abuse",
            severity: "medium",
            description: "Potentially risky JavaScript behavior detected",
          });
          analysis.threatScore += 10;
        }
      }

      // Calculate threat score from malware findings
      malwareFindings.forEach((finding) => {
        analysis.spywareProfile.persistence = true;
        if (finding.severity === "critical") analysis.threatScore += 40;
        else if (finding.severity === "high") analysis.threatScore += 25;
        else if (finding.severity === "medium") analysis.threatScore += 15;
        else analysis.threatScore += 5;
      });

      // Detect keyloggers
      if (this.detectKeylogger(content, file.name)) {
        analysis.keyloggerDetected = true;
        analysis.spywareProfile.surveillance = true;
        analysis.spywareProfile.credentialHarvesting = true;
        analysis.findings.push({
          type: "keylogger",
          severity: "critical",
          description: "Keylogger-related code patterns detected",
        });
        analysis.threatScore += 60;
      }

      // Detect possible data exfiltration behavior
      if (isJavaScript || isHtmlOrCss) {
        if (/http|ftp|upload|post|socket/i.test(content)) {
          analysis.spywareProfile.dataExfiltration = true;

          if (isHtmlOrCss) {
            analysis.spywareProfile.networkContext = "web";
            analysis.threatScore += 5;
          } else if (isJavaScript) {
            analysis.spywareProfile.networkContext = "script";
            analysis.threatScore += 12;
          }
        }
      }

      analysis.threatScore = Math.min(100, analysis.threatScore);
      analysis.spywareProfile.confidenceScore = Math.min(
        100,
        analysis.threatScore +
          (analysis.spywareProfile.surveillance ? 10 : 0) +
          (analysis.spywareProfile.persistence ? 10 : 0) +
          (analysis.spywareProfile.dataExfiltration ? 10 : 0) +
          (analysis.spywareProfile.stealth ? 10 : 0)
      );

      const confidenceScore = analysis.spywareProfile?.confidenceScore || 0;
      const finalScore = Math.min(
        100,
        Math.max(analysis.threatScore, confidenceScore)
      );

      if (finalScore >= 80) analysis.threatLevel = "critical";
      else if (finalScore >= 60) analysis.threatLevel = "high";
      else if (finalScore >= 30) analysis.threatLevel = "medium";
      else if (finalScore >= 15) analysis.threatLevel = "low";
      else analysis.threatLevel = "safe";
    } catch (error) {
      analysis.findings.push({
        type: "error",
        severity: "low",
        description: `Analysis error: ${error.message}`,
      });
    }

    analysis.riskExposure = generateRiskExplanation(analysis);
    return analysis;
  }

  async readFileHeader(file) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const arrayBuffer = e.target.result;
        const bytes = new Uint8Array(arrayBuffer);
        const hex = Array.from(bytes)
          .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
          .join("");
        resolve(hex);
      };
      reader.readAsArrayBuffer(file.slice(0, 32));
    });
  }

  async readFileContent(file) {
    const CHUNK_SIZE = 64 * 1024; // 64 KB
    const samples = [];

    const positions = [
      0,
      Math.max(0, Math.floor(file.size / 2) - CHUNK_SIZE / 2),
      Math.max(0, file.size - CHUNK_SIZE),
    ];

    for (const pos of positions) {
      const slice = file.slice(pos, pos + CHUNK_SIZE);
      const text = await new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result || "");
        reader.readAsText(slice);
      });
      samples.push(text);
    }

    return samples.join("\n");
  }

  detectFileType(header) {
    for (const [type, signatures] of Object.entries(this.fileHeaders)) {
      for (const signature of signatures) {
        if (header.startsWith(signature)) {
          return type;
        }
      }
    }
    return "UNKNOWN";
  }

  checkRTLOSpoofing(filename) {
    // Check for Right-to-Left Override character (U+202E)
    return filename.includes("\u202E") || filename.includes("[U+202E]");
  }

  scanForMalware(content) {
    const findings = [];

    // Check malware signatures
    this.signatureDatabase.malware.forEach((signature) => {
      if (signature.pattern.test(content)) {
        findings.push({
          type: "malware_signature",
          severity: signature.threat,
          description: signature.description,
        });
      }
    });

    // Check suspicious patterns
    this.signatureDatabase.suspicious.forEach((signature) => {
      if (signature.pattern.test(content)) {
        findings.push({
          type: "suspicious_pattern",
          severity: signature.threat,
          description: signature.description,
        });
      }
    });

    return findings;
  }

  detectKeylogger(content, filename) {
    const keyloggerPatterns = [
      /GetAsyncKeyState/i,
      /GetKeyboardState/i,
      /SetWindowsHookEx/i,
      /WH_KEYBOARD_LL/i,
      /keyboard.*hook/i,
      /keystroke.*log/i,
      /key.*press.*log/i,
      /log.*key/i,
      /record.*key/i,
      /capture.*key/i,
      /keylogger/i,
      /key.*stroke/i,
      /typed.*character/i,
      /virtual.*key/i,
      /scan.*code/i,
    ];

    // Check if any keylogger pattern matches
    const hasKeyloggerPattern = keyloggerPatterns.some((pattern) =>
      pattern.test(content)
    );

    // Check filename for keylogger indicators
    const suspiciousFilename = /keylogger|keystroke|keylog|kl/i.test(filename);

    return hasKeyloggerPattern || suspiciousFilename;
  }

  logAnalysisResults(filename, analysis) {
    const threatColors = {
      safe: "green",
      low: "blue",
      medium: "yellow",
      high: "red",
      critical: "red",
    };

    this.logToTerminal(
      `[COMPLETE] ${filename} - Threat Level: ${analysis.threatLevel.toUpperCase()}`,
      threatColors[analysis.threatLevel]
    );

    analysis.findings.forEach((finding) => {
      const color =
        finding.severity === "critical"
          ? "red"
          : finding.severity === "high"
          ? "red"
          : finding.severity === "medium"
          ? "yellow"
          : "blue";
      this.logToTerminal(
        `[${finding.severity.toUpperCase()}] ${finding.description}`,
        color
      );
    });

    this.logToTerminal(
      `[SCORE] Threat Score: ${analysis.threatScore}/100`,
      "blue"
    );
    
    if (analysis.deep_scan) {
      this.logToTerminal(`[DEEP SCAN] Sandbox analysis completed`, "purple");
    }
    
    this.logToTerminal("────────────────────────────────────────", "gray");
  }

  logToTerminal(message, color = "white") {
    const terminal = document.getElementById("terminalOutput");
    if (!terminal) return;
    
    const timestamp = new Date().toLocaleTimeString();
    const colorClass = this.getColorClass(color);

    const logEntry = document.createElement("div");
    logEntry.className = colorClass;
    logEntry.textContent = `[${timestamp}] ${message}`;

    terminal.appendChild(logEntry);
    terminal.scrollTop = terminal.scrollHeight;
  }

  getColorClass(color) {
    const colorMap = {
      white: "text-white",
      green: "text-green-400",
      blue: "text-blue-400",
      yellow: "text-yellow-400",
      red: "text-red-400",
      gray: "text-gray-500",
      purple: "text-purple-400",
    };
    return colorMap[color] || "text-white";
  }

  updateThreatLevel() {
    if (this.analysisResults.size === 0) {
      // Show secure state when no files are analyzed
      const threatPct = document.getElementById("threatPercentage");
      if (threatPct) {
        threatPct.textContent = "—";
        const statusElement = threatPct.nextElementSibling;
        if (statusElement) {
          statusElement.textContent = "NO FILES ANALYZED";
          statusElement.className = "text-xs text-gray-400";
        }
      }

      // Set all bars to 100% (secure) when no files
      const integrityBar = document.getElementById("integrityBar");
      const extensionBar = document.getElementById("extensionBar");
      const permissionBar = document.getElementById("permissionBar");
      
      if (integrityBar) integrityBar.style.width = "100%";
      if (extensionBar) extensionBar.style.width = "100%";
      if (permissionBar) permissionBar.style.width = "100%";

      // Set all bars to green (secure)
      this.updateBarColor("integrityBar", 100);
      this.updateBarColor("extensionBar", 100);
      this.updateBarColor("permissionBar", 100);
      return;
    }

    let totalScore = 0;
    let maxScore = 0;

    this.analysisResults.forEach((analysis) => {
      totalScore += analysis.threatScore;
      maxScore += 100;
    });

    const averageThreat = (totalScore / maxScore) * 100;
    const securityScore = Math.max(0, Math.round(100 - averageThreat));

    // Update threat percentage display
    const threatPct = document.getElementById("threatPercentage");
    if (threatPct) {
      threatPct.textContent = `${Math.round(averageThreat)}%`;

      // Update status based on threat level
      const statusElement = threatPct.nextElementSibling;
      if (statusElement) {
        if (securityScore <= 20) {
          statusElement.textContent = "CRITICAL THREAT";
          statusElement.className = "text-xs text-red-400";
        } else if (securityScore <= 50) {
          statusElement.textContent = "HIGH RISK";
          statusElement.className = "text-xs text-red-400";
        } else if (securityScore <= 75) {
          statusElement.textContent = "MODERATE RISK";
          statusElement.className = "text-xs text-yellow-400";
        } else if (securityScore <= 90) {
          statusElement.textContent = "LOW RISK";
          statusElement.className = "text-xs text-blue-400";
        } else {
          statusElement.textContent = "NO THREAT DETECTED";
          statusElement.className = "text-xs text-green-400";
        }
      }
    }

    // Update progress bars
    this.updateProgressBars(averageThreat);
  }

  updateProgressBars(threatLevel) {
    // Calculate security scores (inverse of threat level)
    const integrity = Math.max(0, 100 - threatLevel);
    const extension = Math.max(0, 100 - threatLevel * 0.8);
    const permission = Math.max(0, 100 - threatLevel * 0.6);

    // Animate the progress bars
    if (typeof anime !== 'undefined') {
      anime({
        targets: "#integrityBar",
        width: `${integrity}%`,
        duration: 1000,
        easing: "easeOutQuart",
      });

      anime({
        targets: "#extensionBar",
        width: `${extension}%`,
        duration: 1000,
        delay: 200,
        easing: "easeOutQuart",
      });

      anime({
        targets: "#permissionBar",
        width: `${permission}%`,
        duration: 1000,
        delay: 400,
        easing: "easeOutQuart",
      });
    } else {
      const integrityBar = document.getElementById("integrityBar");
      const extensionBar = document.getElementById("extensionBar");
      const permissionBar = document.getElementById("permissionBar");
      if (integrityBar) integrityBar.style.width = `${integrity}%`;
      if (extensionBar) extensionBar.style.width = `${extension}%`;
      if (permissionBar) permissionBar.style.width = `${permission}%`;
    }

    // Update bar colors based on threat level
    this.updateBarColor("integrityBar", integrity);
    this.updateBarColor("extensionBar", extension);
    this.updateBarColor("permissionBar", permission);
  }

  updateBarColor(barId, value) {
    const bar = document.getElementById(barId);
    if (!bar) return;
    
    if (value >= 80) {
      bar.className = "h-full bg-green-400 rounded";
    } else if (value >= 60) {
      bar.className = "h-full bg-yellow-400 rounded";
    } else {
      bar.className = "h-full bg-red-400 rounded";
    }
  }

  updateFileQueue() {
    const queueContainer = document.getElementById("fileQueue");
    if (!queueContainer) return;

    if (this.files.length === 0) {
      queueContainer.innerHTML =
        '<div class="text-gray-400 text-center py-8">No files in queue</div>';
      return;
    }

    queueContainer.innerHTML = "";

    this.files.forEach((file) => {
      const analysis = this.analysisResults.get(file.name);
      const threatLevel = analysis ? analysis.threatLevel : "pending";

      const fileCard = document.createElement("div");
      fileCard.className =
        "flex items-start gap-3 p-4 bg-gray-800 rounded-lg flex-wrap sm:flex-nowrap";

      const iconClass = this.getFileIconClass(threatLevel);
      const threatColor = this.getThreatColor(threatLevel);
      
      // Add deep scan indicator
      const deepScanBadge = analysis?.deep_scan 
        ? '<span class="ml-1 text-xs px-1.5 py-0.5 rounded bg-purple-500/30 text-purple-400">DEEP</span>' 
        : '';

      fileCard.innerHTML = `
                <div class="file-icon ${iconClass}">
                    ${this.getFileExtension(file.name)}
                </div>
                <div class="flex-1">
                    <div class="text-white font-medium truncate max-w-[180px] sm:max-w-none">
                        ${file.name}
                    </div>
                    <div class="text-gray-400 text-sm">${this.formatBytes(file.size)}</div>
                </div>
                <div class="text-right sm:text-right w-full sm:w-auto mt-2 sm:mt-0">
                    <div class="text-sm font-medium ${threatColor}">${threatLevel.toUpperCase()}${deepScanBadge}</div>
                    <div class="text-xs text-gray-400">
                        ${
                          analysis
                            ? `THREAT ${analysis.threatScore}/100`
                            : "PENDING ANALYSIS"
                        }
                    </div>
                </div>
            `;

      queueContainer.appendChild(fileCard);
    });
  }

  getFileIconClass(threatLevel) {
    switch (threatLevel) {
      case "safe":
        return "safe-file";
      case "low":
        return "warning-file";
      case "medium":
        return "warning-file";
      case "high":
        return "danger-file";
      case "critical":
        return "danger-file";
      default:
        return "safe-file";
    }
  }

  getThreatColor(threatLevel) {
    switch (threatLevel) {
      case "safe":
        return "text-green-400";
      case "low":
        return "text-blue-400";
      case "medium":
        return "text-yellow-400";
      case "high":
        return "text-red-400";
      case "critical":
        return "text-red-400";
      default:
        return "text-gray-400";
    }
  }

  getFileExtension(filename) {
    const ext = filename.split(".").pop();
    return ext ? ext.toUpperCase().substring(0, 3) : "???";
  }

  updateStats() {
    let safe = 0,
      warning = 0,
      threat = 0;

    this.analysisResults.forEach((analysis) => {
      switch (analysis.threatLevel) {
        case "safe":
          safe++;
          break;
        case "low":
        case "medium":
          warning++;
          break;
        case "high":
        case "critical":
          threat++;
          break;
      }
    });

    const safeCount = document.getElementById("safeCount");
    const warningCount = document.getElementById("warningCount");
    const threatCount = document.getElementById("threatCount");

    if (safeCount) safeCount.textContent = safe;
    if (warningCount) warningCount.textContent = warning;
    if (threatCount) threatCount.textContent = threat;

    // Animate counters
    this.animateCounter("safeCount", safe);
    this.animateCounter("warningCount", warning);
    this.animateCounter("threatCount", threat);
  }

  animateCounter(elementId, targetValue) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const startValue = parseInt(element.textContent) || 0;

    if (typeof anime !== 'undefined') {
      anime({
        targets: { value: startValue },
        value: targetValue,
        duration: 1000,
        easing: "easeOutQuart",
        update: function (anim) {
          element.textContent = Math.round(anim.animatables[0].target.value);
        },
      });
    } else {
      element.textContent = targetValue;
    }
  }

  formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  initializeAnimations() {
    if (typeof Typed !== 'undefined') {
      new Typed("#typed-text", {
        strings: [
          "Advanced File Security Analysis",
          "Malware Detection & Risk Analysis",
          "Extension Spoofing Detection",
          "Keylogger Identification",
          "Real-time Threat Assessment",
        ],
        typeSpeed: 50,
        backSpeed: 30,
        backDelay: 2000,
        loop: true,
      });
    }
    this.setupScrollAnimations();
  }

  setupScrollAnimations() {
    if (typeof anime === 'undefined') return;
    
    const observerOptions = {
      threshold: 0.1,
      rootMargin: "0px 0px -50px 0px",
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          anime({
            targets: entry.target,
            opacity: [0, 1],
            translateY: [50, 0],
            duration: 800,
            easing: "easeOutQuart",
          });
        }
      });
    }, observerOptions);

    document.querySelectorAll(".analysis-card").forEach((card) => {
      card.style.opacity = "0";
      observer.observe(card);
    });
  }

  startMatrixBackground() {
    const canvas = document.getElementById("matrixCanvas");
    if (!canvas) return;
    
    const ctx = canvas.getContext("2d");

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars =
      "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン";
    const charArray = chars.split("");

    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);

    function drawMatrix() {
      ctx.fillStyle = "rgba(10, 10, 10, 0.04)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = "#00ff41";
      ctx.font = `${fontSize}px JetBrains Mono`;

      for (let i = 0; i < drops.length; i++) {
        const text = charArray[Math.floor(Math.random() * charArray.length)];
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
    }

    setInterval(drawMatrix, 35);

    // Resize handler
    window.addEventListener("resize", () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    });
  }
}

// renderDynamicResults function for results.html
function renderDynamicResults(results) {
  const container = document.getElementById("dynamicFileResults");
  if (!container) return;
  
  container.innerHTML = "";

  results.forEach((file, index) => {
    const isAPK =
      file.isAPK === true &&
      file.apkAnalysis &&
      file.apkAnalysis.backendAvailable === true;
    
    const sectionId = `fileDetails_${index}`;
    const aiId = `aiExplain_${index}`;
    
    if (isAPK) {
      renderAPKCard(file, index, container);
      return;
    }

    const card = document.createElement("div");
    card.className = "analysis-card rounded-xl p-6";

    // Determine scan type badge
    let scanBadge = '';
    if (file.deep_scan) {
      scanBadge = `<span class="ml-2 text-xs px-2 py-0.5 rounded bg-purple-500/30 text-purple-400 border border-purple-500/50">🔬 Deep Scan</span>`;
    } else {
      scanBadge = `<span class="ml-2 text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300">Quick Scan</span>`;
    }

    card.innerHTML = `
      <!-- HEADER -->
      <div class="expandable-section flex flex-wrap sm:flex-nowrap justify-between items-start gap-3 p-4 rounded-lg"
           onclick="toggleSection('${sectionId}')">
        <div>
          <h3 class="text-lg font-semibold text-white truncate max-w-[220px] sm:max-w-none">
              ${file.name}
          </h3>
          <p class="text-gray-400 text-sm">
            Threat Level: ${file.threatLevel.toUpperCase()}${scanBadge}
          </p>
        </div>
        <span class="threat-badge threat-${file.threatLevel} mt-2 sm:mt-0">
            ${file.threatLevel}
        </span>
      </div>

      <!-- DETAILS -->
      <div id="${sectionId}" class="hidden mt-6 space-y-6">
        <!-- BASIC INFO -->
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>Threat Score: <span class="text-red-400">${file.threatScore}/100</span></div>
          <div>Keylogger: <span class="text-red-400">
              ${file.keyloggerDetected ? "Detected" : "Not Detected"}
          </span></div>
        </div>

        <!-- SHOW HASHES IF AVAILABLE (from backend) -->
        ${file.hashes ? `
        <div class="mt-4 p-3 bg-black rounded border border-gray-700">
            <h5 class="text-gray-400 text-xs mb-2">FILE HASHES</h5>
            <div class="font-mono text-xs space-y-1 text-gray-300">
                <div>MD5: ${file.hashes.md5}</div>
                <div>SHA1: ${file.hashes.sha1}</div>
                <div>SHA256: ${file.hashes.sha256}</div>
            </div>
        </div>
        ` : ''}
        
        <!-- SHOW ENTROPY IF AVAILABLE -->
        ${file.entropy ? `
        <div class="mt-2 text-sm">
            Entropy: <span class="${file.entropy > 7.5 ? 'text-red-400' : 'text-green-400'}">${file.entropy}/8.0</span>
            ${file.entropy > 7.5 ? '<span class="text-xs text-gray-500 ml-2">(High - possibly packed)</span>' : ''}
        </div>
        ` : ''}
        
        <!-- SHOW VIRUSTOTAL IF AVAILABLE -->
        ${file.virustotal && file.virustotal.found ? `
        <div class="mt-4 p-3 bg-black rounded border ${file.virustotal.malicious > 0 ? 'border-red-500' : 'border-green-500'}">
            <h5 class="text-gray-400 text-xs mb-2">VIRUSTOTAL RESULTS</h5>
            <div class="text-sm">
                <span class="${file.virustotal.malicious > 0 ? 'text-red-400' : 'text-green-400'} font-bold">
                    ${file.virustotal.malicious}/${file.virustotal.total}
                </span>
                <span class="text-gray-400">engines detected this file</span>
            </div>
            ${file.virustotal.malicious > 0 ? `
            <div class="text-xs text-red-400 mt-1">
                ⚠️ This file is known malware!
            </div>
            ` : ''}
        </div>
        ` : ''}
        
        <!-- SANDBOX ANALYSIS SECTION (Only for deep scan) -->
        ${renderSandboxSection(file)}
        
        <!-- RISK EXPOSURE -->
        <div class="text-sm text-gray-300">
          <span class="text-blue-400 font-semibold">
            Risk Context:
          </span>
          ${
            file.riskExposure && file.riskExposure !== "unknown"
              ? file.riskExposure
              : "No high-risk structural indicators identified"
          }
        </div>

        <!-- SPYWARE PROFILE -->
        <div>
            <h4 class="text-white font-semibold mb-2">Spyware Behavior</h4>
            <ul class="text-sm text-gray-300 space-y-1">
                <li>Surveillance: ${
                  file.spywareProfile.surveillance ? "Yes" : "No"
                }</li>
                <li>Persistence: ${
                  file.spywareProfile.persistence ? "Yes" : "No"
                }</li>
                <li>Stealth: ${
                  file.spywareProfile.stealth ? "Yes" : "No"
                }</li>
                <li>
                ${
                  file.spywareProfile.networkContext === "web"
                    ? "Network Activity Detected"
                    : "Data Exfiltration"
                }
                : ${file.spywareProfile.dataExfiltration ? "Yes" : "No"}
                </li>
                <li>Credential Harvesting: ${
                  file.spywareProfile.credentialHarvesting
                    ? "Yes"
                    : "No"
                }</li>
            </ul>
        </div>

        <!-- FINDINGS -->
        <div>
            <h4 class="text-white font-semibold mb-2">Findings (${file.findings.length})</h4>
            <ul class="text-sm text-gray-300 space-y-1">
              ${file.findings
                .map(
                  (f) => `<li class="${f.severity === 'critical' ? 'text-red-400' : f.severity === 'high' ? 'text-yellow-400' : 'text-gray-300'}">• ${f.description} (${f.severity}${f.source === 'sandbox' ? ' - sandbox' : ''})</li>`
                )
                .join("")}
            </ul>  
        </div>
        
        <!-- AI EXPLANATION -->
        <div class="analysis-card p-4">
          <h4 class="text-blue-400 font-semibold mb-1">
            AI-Assisted Threat Explanation
          </h4>
          <p id="${aiId}" class="text-gray-300 text-sm mb-2">
            AI is analyzing this file…
          </p>
          <span id="${aiId}_badge" class="text-xs text-gray-500">
            Explanation source: checking backend…
          </span>
        </div>
      </div>
    `;

    container.appendChild(card);

    // Call AI explanation
    if (!isAPK) {
      runAIExplanation(file, aiId);
    }
  });
}

function renderSandboxSection(file) {
  if (!file.deep_scan || !file.sandbox_data) return '';
  
  const sd = file.sandbox_data;
  const verdict = sd.verdict || 'unknown';
  
  // Verdict badges
  let verdictBadges = '';
  if (verdict === 'malicious') {
    verdictBadges += `<span class="px-2 py-1 bg-red-500 bg-opacity-30 text-red-400 text-xs rounded mr-2">🚨 MALICIOUS</span>`;
  } else if (verdict === 'suspicious') {
    verdictBadges += `<span class="px-2 py-1 bg-yellow-500 bg-opacity-30 text-yellow-400 text-xs rounded mr-2">⚠️ SUSPICIOUS</span>`;
  } else {
    verdictBadges += `<span class="px-2 py-1 bg-green-500 bg-opacity-20 text-green-400 text-xs rounded mr-2">✅ CLEAN</span>`;
  }
  
  // Network stats
  const networkHtml = sd.network_connections !== undefined ? `
    <div class="mb-4">
      <h4 class="text-gray-400 text-sm mb-2 font-semibold uppercase tracking-wider">🌐 Network Activity</h4>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
        <div class="p-3 rounded-lg bg-gray-800 border border-gray-700 text-center">
          <div class="text-2xl font-bold text-blue-400">${sd.processes_spawned || 0}</div>
          <div class="text-xs text-gray-500">Processes</div>
        </div>
        <div class="p-3 rounded-lg ${sd.network_connections > 0 ? 'bg-yellow-900/30 border-yellow-500' : 'bg-gray-800 border-gray-700'} text-center">
          <div class="text-2xl font-bold ${sd.network_connections > 0 ? 'text-yellow-400' : 'text-green-400'}">${sd.network_connections || 0}</div>
          <div class="text-xs text-gray-500">Network Connections</div>
        </div>
        <div class="p-3 rounded-lg bg-gray-800 border border-gray-700 text-center">
          <div class="text-2xl font-bold text-purple-400">${sd.domains_contacted?.length || 0}</div>
          <div class="text-xs text-gray-500">Domains Contacted</div>
        </div>
        <div class="p-3 rounded-lg bg-gray-800 border border-gray-700 text-center">
          <div class="text-2xl font-bold text-cyan-400">${sd.extracted_files_count || 0}</div>
          <div class="text-xs text-gray-500">Files Dropped</div>
        </div>
      </div>
    </div>
  ` : '';
  
  // MITRE ATT&CK techniques
  const mitreHtml = sd.mitre_techniques && sd.mitre_techniques.length > 0 ? `
    <div class="mb-4">
      <h4 class="text-gray-400 text-sm mb-2 font-semibold uppercase tracking-wider">🎯 MITRE ATT&CK Techniques</h4>
      <div class="flex flex-wrap gap-2">
        ${sd.mitre_techniques.slice(0, 5).map(t => `<span class="px-3 py-1 bg-red-900/30 border border-red-500/50 text-red-400 text-sm rounded-full">${t}</span>`).join('')}
      </div>
    </div>
  ` : '';
  
  // Environment info
  const envHtml = sd.environment ? `
    <div class="mb-4">
      <h4 class="text-gray-400 text-sm mb-2 font-semibold uppercase tracking-wider">🖥️ Sandbox Environment</h4>
      <div class="grid grid-cols-2 md:grid-cols-3 gap-2 text-sm">
        <div class="p-2 rounded bg-gray-800"><span class="text-gray-500">Environment:</span> <span class="text-gray-300">${sd.environment}</span></div>
        <div class="p-2 rounded bg-gray-800"><span class="text-gray-500">Analysis Time:</span> <span class="text-gray-300">${sd.analysis_time || 'N/A'}s</span></div>
        <div class="p-2 rounded bg-gray-800"><span class="text-gray-500">Packer:</span> <span class="text-gray-300">${sd.packer || 'None'}</span></div>
      </div>
    </div>
  ` : '';
  
  // Report link
  const reportHtml = sd.report_url ? `
    <div class="mt-4">
      <a href="${sd.report_url}" target="_blank" class="inline-flex items-center px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded-lg transition-colors">
        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
        </svg>
        View Full Sandbox Report
      </a>
    </div>
  ` : '';
  
  return `
    <div class="mb-6 p-4 rounded-lg bg-purple-900/20 border border-purple-500/50">
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-purple-400 font-semibold flex items-center text-lg">
          <span class="mr-2">🔬</span> Hybrid Analysis Sandbox
        </h4>
        <div>${verdictBadges}</div>
      </div>
      
      ${networkHtml}
      ${mitreHtml}
      ${envHtml}
      ${reportHtml}
    </div>
  `;
}

function renderAPKCard(file, index, container) {
  const apkSectionId = `apkDetails_${index}`;
  
  const card = document.createElement("div");
  card.className = "analysis-card rounded-xl p-6 border border-blue-500/40";

  // Deep scan badge for APK
  const deepScanBadge = file.deep_scan 
    ? `<span class="ml-2 text-xs px-2 py-0.5 rounded bg-purple-500/30 text-purple-400 border border-purple-500/50">🔬 Deep Scan</span>`
    : '';

  card.innerHTML = `
    <div class="expandable-section flex justify-between items-center p-4 rounded-lg"
         onclick="toggleSection('${apkSectionId}')">
      <div>
        <h3 class="text-lg font-semibold text-white">
          📱 ${file.name}
        </h3>
        <p class="text-gray-400 text-sm">
          Android APK Security Analysis${deepScanBadge}
        </p>
      </div>

      <span class="threat-badge threat-${file.apkAnalysis?.riskLevel || "unknown"}">
        ${(file.apkAnalysis?.riskLevel || "unknown").toUpperCase()}
      </span>
    </div>
    
    <div id="${apkSectionId}" class="hidden mt-6 space-y-6">
    
      <!-- BASIC INFO -->
      <div class="grid grid-cols-2 gap-4 text-sm">
        <div>
          Risk Score:
          <span class="text-red-400 font-semibold">
            ${file.apkAnalysis.riskScore}/100
          </span>
        </div>
        <div>
          Verdict:
          <span class="text-red-400 font-semibold">
            ${file.apkAnalysis.riskLevel.toUpperCase()}
          </span>
        </div>
      </div>
    
      <!-- SHOW HASHES IF AVAILABLE (MERGED FROM FILE SCANNER) -->
      ${file.hashes && Object.keys(file.hashes).length > 0 ? `
      <div class="mt-4 p-3 bg-black rounded border border-gray-700">
        <h5 class="text-gray-400 text-xs mb-2">FILE HASHES</h5>
        <div class="font-mono text-xs space-y-1 text-gray-300">
          <div>MD5: ${file.hashes.md5 || 'N/A'}</div>
          <div>SHA1: ${file.hashes.sha1 || 'N/A'}</div>
          <div>SHA256: ${file.hashes.sha256 || 'N/A'}</div>
        </div>
      </div>
      ` : ''}
      
      <!-- SHOW ENTROPY IF AVAILABLE -->
      ${file.entropy ? `
      <div class="mt-2 text-sm">
        Entropy: <span class="${file.entropy > 7.5 ? 'text-red-400' : 'text-green-400'}">${file.entropy}/8.0</span>
        ${file.entropy > 7.5 ? '<span class="text-xs text-gray-500 ml-2">(High - possibly packed)</span>' : ''}
      </div>
      ` : ''}
      
      <!-- SHOW VIRUSTOTAL IF AVAILABLE -->
      ${file.virustotal && file.virustotal.found ? `
      <div class="mt-4 p-3 bg-black rounded border ${file.virustotal.malicious > 0 ? 'border-red-500' : 'border-green-500'}">
        <h5 class="text-gray-400 text-xs mb-2">VIRUSTOTAL RESULTS</h5>
        <div class="text-sm">
          <span class="${file.virustotal.malicious > 0 ? 'text-red-400' : 'text-green-400'} font-bold">
            ${file.virustotal.malicious}/${file.virustotal.total}
          </span>
          <span class="text-gray-400">engines detected this APK</span>
        </div>
        ${file.virustotal.malicious > 0 ? `
        <div class="text-xs text-red-400 mt-1">
          ⚠️ This APK is known malware!
        </div>
        ` : ''}
      </div>
      ` : ''}
      
      <!-- SANDBOX SECTION FOR APK -->
      ${renderSandboxSection(file)}
        
      <!-- SHOW MERGED FINDINGS -->
      ${file.findings && file.findings.length > 0 ? `
      <div>
        <h4 class="text-white font-semibold mb-2">Security Findings</h4>
        <ul class="text-sm text-gray-300 space-y-1">
          ${file.findings.map(f => `
            <li class="${f.severity === 'critical' ? 'text-red-400' : f.severity === 'high' ? 'text-yellow-400' : 'text-gray-300'}">
              • ${f.description || f.rule || f.type} (${f.severity}${f.source === 'sandbox' ? ' - sandbox' : ''})
            </li>
          `).join('')}
        </ul>
      </div>
      ` : ''}
          
      <!-- RISK EXPLANATION -->
      <div class="text-sm text-gray-300">
        <span class="text-blue-400 font-semibold">
          Risk Context:
        </span>
        <p class="mt-2">
          ${file.apkAnalysis.explanation || "No explanation available"}
        </p>
      </div>
          
      <!-- DANGEROUS PERMISSIONS -->
      <div>
        <h4 class="text-white font-semibold mb-2">
          Dangerous Permissions
        </h4>
        <ul class="list-disc ml-5 text-sm text-gray-300 space-y-1">
          ${
            file.apkAnalysis.riskyPermissions.length
              ? file.apkAnalysis.riskyPermissions
                  .map(
                    (p) =>
                      `<li>
                        <span class="text-red-400">${p.permission}</span>
                        <span class="text-gray-400">
                          (${p.severity}) – ${p.reason}
                        </span>
                      </li>`
                  )
                  .join("")
              : "<li>No high-risk permissions detected</li>"
          }
        </ul>
      </div>
        
      <div class="text-xs text-gray-500">
        ${file.deep_scan ? 'Merged analysis: Permissions + File Intelligence + Sandbox • Runtime execution analyzed' : 'Merged analysis: Permissions + File Intelligence • No runtime execution'}
      </div>
    </div>
  `;
        
  container.appendChild(card);
}

function showAIQuotaMessage() {
  if (sessionStorage.getItem("quotaMsgShown") === "true") return;

  sessionStorage.setItem("quotaMsgShown", "true");

  showNotification(
    "AI quota exhausted. Showing heuristic-based explanations for now.",
    "warning"
  );
}

async function runAIExplanation(file, targetId) {
  if (file._aiRequested) return;
  file._aiRequested = true;
  const element = document.getElementById(targetId);
  if (!element) return;

  element.textContent = "Analyzing threat behavior using AI…";

  const payload = {
    analysis_type: "file",
    target: file.name,
    threat_score: file.threatScore,
    threat_level: file.threatLevel,
    findings: file.findings.map((f) => f.description),
  };

  // Try backend AI first
  try {
    const response = await fetch(
      "https://zerorisk-sentinel-backend.onrender.com/api/ai-explain",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }
    );

    if (response.ok) {
      const data = await response.json();
      if (data.ai_explanation && !data.fallback) {
        
        element.textContent =
          typeof data.ai_explanation === "string"
            ? data.ai_explanation
            : data.ai_explanation.text;

        const badge = document.getElementById(targetId + "_badge");
        if (badge) {
          badge.textContent = "Explanation source: AI-assisted";
        }
        return;
      }

      if (data.fallback) {
        const aiCard = element.closest(".analysis-card");
        const title = aiCard?.querySelector("h4");
      
        if (title) {
          title.textContent = "AI-Assisted (Quota Exhausted)";
          title.classList.remove("text-blue-400");
          title.classList.add("text-gray-400");
        }
      
        const badge = document.getElementById(targetId + "_badge");
        if (badge) {
          badge.textContent = "Explanation source: heuristic (quota exhausted)";
        }
      
        showAIQuotaMessage();
      }
    }
  } catch (e) {
    // silently fail → fallback below
  }

  const explanation = [];

  if (file.threatLevel === "critical" || file.threatLevel === "high") {
    explanation.push(
      "This file exhibits multiple coordinated behaviors commonly associated with spyware or malicious software. These indicators suggest elevated security risk, though static analysis alone cannot confirm intent."
    );
  }

  if (file.spywareProfile?.surveillance) {
    explanation.push(
      "Indicators suggest potential monitoring of user activity or system behavior without clear user awareness."
    );
  }

  if (file.spywareProfile?.credentialHarvesting) {
    explanation.push(
      "Patterns consistent with credential collection were identified, which may expose sensitive user information."
    );
  }

  if (file.spywareProfile?.persistence) {
    explanation.push(
      "The file shows signs of persistence mechanisms that could allow it to remain active across system restarts."
    );
  }

  if (file.spywareProfile?.dataExfiltration) {
    explanation.push(
      "Network-capable functionality was detected. While not conclusively malicious, such behavior can be abused for unauthorized data transmission."
    );
  }

  if (file.keyloggerDetected) {
    explanation.push(
      "Keystroke monitoring indicators were detected, which may allow the capture of typed input such as passwords or messages."
    );
  }

  if (explanation.length === 0) {
    explanation.push(
      "No overtly malicious payloads were identified through static analysis. However, structural indicators suggest caution is warranted."
    );
  }

  element.textContent = explanation.join(" ");
  const badge = document.getElementById(targetId + "_badge");
  if (badge) {
    badge.textContent = "Explanation source: heuristic (offline mode)";
  }
}

// Initialize the application when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new CyberGuardSpywareAnalyzer();
  
  if (typeof updateBackendStatus === 'function') {
    updateBackendStatus();
    setInterval(updateBackendStatus, 30000);
  }
  // Backend warning dismissal
function dismissBackendWarning() {
    const warning = document.getElementById('backendWarning');
    if (warning) {
        warning.style.opacity = '0';
        warning.style.transform = 'translateX(-50%) translateY(-20px)';
        warning.style.transition = 'all 0.3s ease';
        setTimeout(() => warning.remove(), 300);
    }
}

// Auto-hide warning when backend becomes active
const backendCheckInterval = setInterval(() => {
    const statusText = document.getElementById('backendStatusText');
    const warning = document.getElementById('backendWarning');
    
    if (statusText && warning) {
        if (statusText.textContent.includes('Backend Active')) {
            warning.style.opacity = '0';
            warning.style.transform = 'translateX(-50%) translateY(-20px)';
            warning.style.transition = 'all 0.5s ease';
            setTimeout(() => warning.remove(), 500);
            clearInterval(backendCheckInterval);
        }
    }
}, 2000);
});

// Add some utility functions for enhanced functionality
function showNotification(message, type = "info") {
  // Create notification element
  const notification = document.createElement("div");
  notification.className = `fixed top-20 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm ${
    type === "success"
      ? "bg-green-600"
      : type === "warning"
      ? "bg-yellow-600"
      : type === "error"
      ? "bg-red-600"
      : "bg-blue-600"
  } text-white`;

  notification.innerHTML = `
        <div class="flex items-center space-x-3">
            <div class="flex-shrink-0">
                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                </svg>
            </div>
            <div class="flex-1">
                <p class="text-sm font-medium">${message}</p>
            </div>
            <div class="flex-shrink-0">
                <button onclick="this.parentElement.parentElement.parentElement.remove()" class="text-white hover:text-gray-200">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                    </svg>
                </button>
            </div>
        </div>
    `;

  document.body.appendChild(notification);

  // Animate in
  if (typeof anime !== 'undefined') {
    anime({
      targets: notification,
      translateX: [300, 0],
      opacity: [0, 1],
      duration: 300,
      easing: "easeOutQuart",
    });
  }

  // Auto remove after 5 seconds
  setTimeout(() => {
    if (typeof anime !== 'undefined') {
      anime({
        targets: notification,
        translateX: [0, 300],
        opacity: [1, 0],
        duration: 300,
        easing: "easeInQuart",
        complete: () => notification.remove(),
      });
    } else {
      notification.remove();
    }
  }, 5000);
}

// Analysis dropdown functionality
function toggleAnalysisDropdown(type) {
  const dropdown = document.getElementById(type + "Dropdown");
  const icon = dropdown.previousElementSibling.querySelector(".dropdown-icon");

  if (dropdown.classList.contains("hidden")) {
    dropdown.classList.remove("hidden");
    icon.classList.add("rotated");

    if (typeof anime !== 'undefined') {
      anime({
        targets: dropdown,
        opacity: [0, 1],
        maxHeight: [0, "1000px"],
        duration: 500,
        easing: "easeOutQuart",
      });
    }
  } else {
    if (typeof anime !== 'undefined') {
      anime({
        targets: dropdown,
        opacity: [1, 0],
        maxHeight: ["1000px", 0],
        duration: 300,
        easing: "easeInQuart",
        complete: () => {
          dropdown.classList.add("hidden");
          icon.classList.remove("rotated");
        },
      });
    } else {
      dropdown.classList.add("hidden");
      icon.classList.remove("rotated");
    }
  }
}

// Toggle section function for results.html
function toggleSection(sectionId) {
  const section = document.getElementById(sectionId);
  if (!section) return;
  
  const button = section.previousElementSibling;
  const icon = button?.querySelector(".expand-icon");

  if (section.classList.contains("hidden")) {
    section.classList.remove("hidden");
    if (button) button.classList.add("expanded");

    if (typeof anime !== 'undefined') {
      anime({
        targets: section,
        opacity: [0, 1],
        maxHeight: [0, "2000px"],
        duration: 500,
        easing: "easeOutQuart",
      });
    }
  } else {
    if (typeof anime !== 'undefined') {
      anime({
        targets: section,
        opacity: [1, 0],
        maxHeight: ["2000px", 0],
        duration: 300,
        easing: "easeInQuart",
        complete: () => {
          section.classList.add("hidden");
          if (button) button.classList.remove("expanded");
        },
      });
    } else {
      section.classList.add("hidden");
      if (button) button.classList.remove("expanded");
    }
  }
}

// Scan mode functions
function setScanMode(mode) {
  const liveBtn = document.getElementById('liveModeBtn');
  const demoBtn = document.getElementById('demoModeBtn');
  const demoSamples = document.getElementById('demoSamples');
  
  if (liveBtn && demoBtn) {
    if (mode === 'live') {
      liveBtn.className = 'px-4 py-2 rounded-lg bg-blue-600 text-white font-medium';
      demoBtn.className = 'px-4 py-2 rounded-lg bg-gray-700 text-gray-300 font-medium hover:bg-gray-600';
      if (demoSamples) demoSamples.classList.add('hidden');
    } else {
      demoBtn.className = 'px-4 py-2 rounded-lg bg-blue-600 text-white font-medium';
      liveBtn.className = 'px-4 py-2 rounded-lg bg-gray-700 text-gray-300 font-medium hover:bg-gray-600';
      if (demoSamples) demoSamples.classList.remove('hidden');
    }
  }
  
  sessionStorage.setItem('scanMode', mode);
}

// Deep scan toggle function
function toggleDeepScan(enabled) {
  const track = document.getElementById('deepScanTrack');
  const thumb = document.getElementById('deepScanThumb');
  
  if (track && thumb) {
    if (enabled) {
      track.classList.remove('bg-gray-700');
      track.classList.add('bg-purple-600');
      thumb.classList.add('translate-x-5');
    } else {
      track.classList.add('bg-gray-700');
      track.classList.remove('bg-purple-600');
      thumb.classList.remove('translate-x-5');
    }
  }
  
  sessionStorage.setItem('deepScan', enabled ? 'on' : 'off');
}

// Backend status update function
async function updateBackendStatus() {
  const statusDot = document.getElementById('backendStatusDot');
  const statusText = document.getElementById('backendStatusText');
  
  if (!statusDot || !statusText) return;
  
  try {
    const res = await fetch(`${BACKEND_URL}/api/status`);
    if (res.ok) {
      const data = await res.json();
      
      if (data.file_scanner?.available) {
        if (data.file_scanner?.yara_loaded) {
          statusDot.className = 'w-2 h-2 rounded-full bg-green-400';
          statusText.textContent = 'Backend Active (Better scanning)';
        } else {
          statusDot.className = 'w-2 h-2 rounded-full bg-yellow-400';
          statusText.textContent = 'Backend Online';
        }
      } else {
        statusDot.className = 'w-2 h-2 rounded-full bg-yellow-400';
        statusText.textContent = 'Backend Limited';
      }
    } else {
      statusDot.className = 'w-2 h-2 rounded-full bg-red-400';
      statusText.textContent = 'Backend Offline (Local Mode)';
    }
  } catch (e) {
    statusDot.className = 'w-2 h-2 rounded-full bg-red-400';
    statusText.textContent = 'Backend Offline (Local Mode)';
  }
}

// Info Modal Functions
const modalInfo = {
  deepScan: {
    title: "Deep Scan Mode",
    content: "Deep Scan runs files in an isolated sandbox environment to analyze runtime behavior, API calls, and network activity. Detects zero-day threats and obfuscated malware that signature-based scans miss. Takes longer but provides maximum security assurance."
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
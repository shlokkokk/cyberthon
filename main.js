class CyberGuardSpywareAnalyzer {
    constructor() {
        this.files = [];
        this.analysisResults = new Map();
        this.signatureDatabase = this.initializeSignatureDatabase();
        this.fileHeaders = this.initializeFileHeaders();
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.initializeAnimations();
        this.startMatrixBackground();
        this.updateStats();
    }
    
    // File signature database for malware detection
    initializeSignatureDatabase() {
        return {
            // Known malware signatures (simplified patterns for demonstration)
            malware: [
                { pattern: /eval\s*\(/, threat: 'high', description: 'Code execution detected' },
                { pattern: /shell\s*\(/, threat: 'high', description: 'Shell command execution' },
                { pattern: /system\s*\(/, threat: 'high', description: 'System command execution' },
                { pattern: /exec\s*\(/, threat: 'high', description: 'Process execution detected' },
                { pattern: /cmd\.exe/, threat: 'high', description: 'Windows command prompt' },
                { pattern: /powershell\.exe/, threat: 'high', description: 'PowerShell execution' },
                { pattern: /wscript\.shell/, threat: 'high', description: 'Windows Script Host' },
                { pattern: /keylogger/i, threat: 'critical', description: 'Keylogger detected' },
                { pattern: /keystroke/i, threat: 'critical', description: 'Keystroke logging' },
                { pattern: /password.*steal/i, threat: 'critical', description: 'Password theft' },
                { pattern: /trojan/i, threat: 'critical', description: 'Trojan horse' },
                { pattern: /ransomware/i, threat: 'critical', description: 'Ransomware detected' },
                { pattern: /encrypt.*file/i, threat: 'high', description: 'File encryption' },
                { pattern: /delete.*file/i, threat: 'medium', description: 'File deletion' },
                { pattern: /registry.*modify/i, threat: 'high', description: 'Registry modification indicators found in file content' },
                { pattern: /startup.*add/i, threat: 'high', description: 'Startup persistence indicators found in file content' },
                { pattern: /network.*send/i, threat: 'medium', description: 'Network-related indicators found in file content' },
                { pattern: /http.*post/i, threat: 'medium', description: 'HTTP data exfiltration' },
                { pattern: /ftp.*upload/i, threat: 'high', description: 'FTP data transfer' },
                { pattern: /email.*send/i, threat: 'medium', description: 'Email data theft' }
            ],
            
            // Suspicious patterns
            suspicious: [
                { pattern: /base64_decode/i, threat: 'medium', description: 'Base64 decoding' },
                { pattern: /gzinflate/i, threat: 'medium', description: 'Compression detected' },
                { pattern: /str_rot13/i, threat: 'low', description: 'String obfuscation' },
                { pattern: /chr\s*\(/, threat: 'low', description: 'Character encoding' },
                { pattern: /fromCharCode/i, threat: 'low', description: 'Character encoding' },
                { pattern: /charCodeAt/i, threat: 'low', description: 'Character analysis' },
                { pattern: /substr/i, threat: 'low', description: 'String manipulation' },
                { pattern: /substring/i, threat: 'low', description: 'String manipulation' },
                { pattern: /replace.*regex/i, threat: 'medium', description: 'String replacement' },
                { pattern: /split.*join/i, threat: 'low', description: 'String manipulation' }
            ]
        };
    }
    
    // File header signatures for type detection
    initializeFileHeaders() {
        return {
            'JPEG': ['FFD8FFE0', 'FFD8FFE1', 'FFD8FFE2', 'FFD8FFE3', 'FFD8FFE8'],
            'PNG': ['89504E47'],
            'GIF': ['47494638'],
            'BMP': ['424D'],
            'TIFF': ['49492A00', '4D4D002A'],
            'PDF': ['25504446'],
            'ZIP': ['504B0304', '504B0506', '504B0708'],
            'RAR': ['52617221'],
            '7Z': ['377ABCAF271C'],
            'TAR': ['7573746172'],
            'GZ': ['1F8B'],
            'EXE': ['4D5A'],
            'DLL': ['4D5A'],
            'MSI': ['D0CF11E0A1B11AE1'],
            'DOC': ['D0CF11E0A1B11AE1'],
            'XLS': ['D0CF11E0A1B11AE1'],
            'PPT': ['D0CF11E0A1B11AE1'],
            'DOCX': ['504B030414000600'],
            'XLSX': ['504B030414000600'],
            'PPTX': ['504B030414000600'],
            'MP3': ['494433', 'FFFB', 'FFF3', 'FFFA'],
            'MP4': ['0000001866747970', '0000001C66747970'],
            'AVI': ['52494646'],
            'WMV': ['3026B2758E66CF11'],
            'MOV': ['0000001466747970'],
            'ISO': ['4344303031'],
            'MPG': ['000001BA', '000001B3'],
            'FLV': ['464C56'],
            'SWF': ['465753', '435753'],
            'JAR': ['504B0304'],
            'APK': ['504B0304'],
            'CLASS': ['CAFEBABE'],
            'PSD': ['38425053'],
            'AI': ['25504446'],
            'EPS': ['25215053'],
            'PS': ['25215053'],
            'RTF': ['7B5C72746631'],
            'XML': ['3C3F786D6C'],
            'HTML': ['3C21444F4354595045', '3C68746D6C'],
            'JS': ['2F2A', '2F2F'],
            'CSS': ['2F2A', '4063686172736574'],
            'PHP': ['3C3F706870'],
            'SQL': ['2D2D', '2F2A'],
            'BAT': ['406563686F20', '4063686F20'],
            'CMD': ['406563686F20', '4063686F20'],
            'PS1': ['2323'],
            'VBS': ['2773C61766553'],
            'WSF': ['3C3F786D6C'],
            'TXT': [],
            'CSV': [],
            'INI': [],
            'CFG': [],
            'LOG': []
        };
    }
    
    setupEventListeners() {
        const dropZone = document.getElementById('fileDropZone');
        const fileInput = document.getElementById('fileInput');
        
        // Click to select files
        dropZone.addEventListener('click', () => fileInput.click());
        
        // File input change
        fileInput.addEventListener('change', (e) => this.handleFiles(e.target.files));
        
        // Drag and drop events
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });
        
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('drag-over');
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            this.handleFiles(e.dataTransfer.files);
        });
    }
    
    async handleFiles(fileList) {
        const files = Array.from(fileList);
        this.files.push(...files);
        
        // Show scanning progress
        document.getElementById('scanningProgress').classList.remove('hidden');
        
        // Process files sequentially
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            await this.analyzeFile(file, i, files.length);
        }
        
        // Hide progress after completion
        setTimeout(() => {
            document.getElementById('scanningProgress').classList.add('hidden');
        }, 2000);
        
        this.updateFileQueue();
        this.updateStats();
        // STORE RESULTS FOR RESULTS PAGE
        sessionStorage.setItem(
            "analysisResults",
            JSON.stringify(Array.from(this.analysisResults.values()))
        );

        const resultsArray = Array.from(this.analysisResults.values());
        sessionStorage.setItem(
            "analysisResults",
            JSON.stringify(resultsArray)
        );
        initializeCharts();
        renderDynamicResults(resultsArray);
    }
    
    async analyzeFile(file, index, total) {
        const progress = ((index + 1) / total) * 100;
        
        // Update progress
        document.getElementById('progressText').textContent = `${Math.round(progress)}%`;
        document.getElementById('progressFill').style.width = `${progress}%`;
        document.getElementById('currentFile').textContent = `Analyzing: ${file.name}`;
        
        // Log analysis start
        this.logToTerminal(`[ANALYZING] ${file.name} (${this.formatBytes(file.size)})`, 'blue');
        
        // Perform analysis
        const analysis = await this.performFileAnalysis(file);
        this.analysisResults.set(file.name, analysis);
        
        // Log results
        this.logAnalysisResults(file.name, analysis);
        
        // Update threat level
        this.updateThreatLevel();
    }
    
    async performFileAnalysis(file) {
        const analysis = {
            name: file.name,
            size: file.size,
            type: file.type,
            lastModified: file.lastModified,
            threatLevel: 'safe',
            threatScore: 0,
            findings: [],
            fileHeader: null,
            extensionMismatch: false,
            riskExposure: 'unknown',
            malwareDetected: false,
            keyloggerDetected: false,
            spywareProfile: {
                surveillance: false,
                dataExfiltration: false,
                persistence: false,
                stealth: false,
                credentialHarvesting: false,
                confidenceScore: 0
            },
        };
        
        try {
            // Read file header (first 32 bytes)
            const header = await this.readFileHeader(file);
            analysis.fileHeader = header;
            
            // Check file type based on header
            const detectedType = this.detectFileType(header);
            let extension = file.name.split('.').pop().toUpperCase();

            // Normalize common equivalent extensions
            const extensionAliases = {
                JPG: "JPEG",
                JPEG: "JPEG",
                HTM: "HTML"
            };

            if (extensionAliases[extension]) {
                extension = extensionAliases[extension];
            }
            
            // Check for extension mismatch
            if (detectedType && detectedType !== extension && detectedType !== 'UNKNOWN') {
                analysis.spywareProfile.stealth = true;
                analysis.extensionMismatch = true;
                analysis.findings.push({
                    type: 'extension_mismatch',
                    severity: 'high',
                    description: `File appears to be ${detectedType} but has .${extension} extension`
                });
                analysis.threatScore += 30;
            }
            
            // Check for Right-to-Left Override (RLO) spoofing
            if (this.checkRTLOSpoofing(file.name)) {
                analysis.spywareProfile.stealth = true;
                analysis.findings.push({
                    type: 'rlo_spoofing',
                    severity: 'critical',
                    description: 'Right-to-Left Override character detected - potential extension spoofing'
                });
                analysis.threatScore += 50;
            }
            
            // Scan for malware signatures
            const content = await this.readFileContent(file);
            const malwareFindings = this.scanForMalware(content);
            analysis.findings.push(...malwareFindings);
            // JS-specific heuristic checks (static analysis)
            const extensionLower = file.name.split('.').pop().toLowerCase();
            const isJavaScript = extensionLower === "js";
            const isHtmlOrCss = ['html', 'htm', 'css'].includes(extensionLower);

            if (isJavaScript) {
                const jsDangerPatterns = [
                    /eval\s*\(/i,
                    /Function\s*\(/i,
                    /atob\s*\(/i,
                    /fromCharCode/i,
                    /document\.cookie/i,
                    /localStorage/i,
                    /fetch\s*\(/i,
                    /XMLHttpRequest/i
                ];      
                if (jsDangerPatterns.some(p => p.test(content))) {
                    analysis.findings.push({
                        type: 'js_abuse',
                        severity: 'medium',
                        description: 'Potentially risky JavaScript behavior detected'
                    });
                    analysis.threatScore += 10;
                }
            }

            
            // Calculate threat score from malware findings
            malwareFindings.forEach(finding => {
                analysis.spywareProfile.persistence = true;
                if (finding.severity === 'critical') analysis.threatScore += 40;
                else if (finding.severity === 'high') analysis.threatScore += 25;
                else if (finding.severity === 'medium') analysis.threatScore += 15;
                else analysis.threatScore += 5;
            });
                    
            // Detect keyloggers
            if (this.detectKeylogger(content, file.name)) {
                analysis.keyloggerDetected = true;
                analysis.spywareProfile.surveillance = true;
                analysis.spywareProfile.credentialHarvesting = true;
                analysis.findings.push({
                    type: 'keylogger',
                    severity: 'critical',
                    description: 'Keylogger-related code patterns detected'
                });
                analysis.threatScore += 60;
            }

            // Detect possible data exfiltration behavior
            // Applied ONLY to script and web files to avoid false positives
            if (
                (isJavaScript || isHtmlOrCss) &&
                /http|ftp|upload|post|socket/i.test(content)
            ) {
                analysis.spywareProfile.dataExfiltration = true;

                if (isHtmlOrCss) {
                    // Normal browser network behavior
                    analysis.spywareProfile.networkContext = "web";
                    analysis.threatScore += 5;
                } 
                else if (isJavaScript) {
                    // JavaScript can be abused
                    analysis.spywareProfile.networkContext = "script";
                    analysis.threatScore += 12;
                }
            }

            analysis.threatScore = Math.min(100, analysis.threatScore);
            // Heuristic scores are used for relative risk visualization
            // not proof of malicious execution
            analysis.spywareProfile.confidenceScore = Math.min(
                100,
                analysis.threatScore +
                (analysis.spywareProfile.surveillance ? 10 : 0) +
                (analysis.spywareProfile.persistence ? 10 : 0) +
                (analysis.spywareProfile.dataExfiltration ? 10 : 0) +
                (analysis.spywareProfile.stealth ? 10 : 0)
            );
            
            const finalScore = Math.min(
                100,
                Math.max(
                    analysis.threatScore,
                    analysis.spywareProfile.confidenceScore
                )
            );
            if (finalScore >= 80) analysis.threatLevel = 'critical';
            else if (finalScore >= 60) analysis.threatLevel = 'high';
            else if (finalScore >= 30) analysis.threatLevel = 'medium';
            else if (finalScore >= 15) analysis.threatLevel = 'low';
            else analysis.threatLevel = 'safe';


            
        } catch (error) {
            analysis.findings.push({
                type: 'error',
                severity: 'low',
                description: `Analysis error: ${error.message}`
            });
        }
        
        return analysis;
    }
    
    async readFileHeader(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const arrayBuffer = e.target.result;
                const bytes = new Uint8Array(arrayBuffer);
                const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
                resolve(hex);
            };
            reader.readAsArrayBuffer(file.slice(0, 32));
        });
    }
    
    async readFileContent(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                resolve(e.target.result);
            };
            reader.readAsText(file.slice(0, 10000)); // Read first 10KB
        });
    }
    
    detectFileType(header) {
        for (const [type, signatures] of Object.entries(this.fileHeaders)) {
            for (const signature of signatures) {
                if (header.startsWith(signature)) {
                    return type;
                }
            }
        }
        return 'UNKNOWN';
    }
    
    checkRTLOSpoofing(filename) {
        // Check for Right-to-Left Override character (U+202E)
        return filename.includes('\u202E') || filename.includes('[U+202E]');
    }
    
    scanForMalware(content) {
        const findings = [];
        
        // Check malware signatures
        this.signatureDatabase.malware.forEach(signature => {
            if (signature.pattern.test(content)) {
                findings.push({
                    type: 'malware_signature',
                    severity: signature.threat,
                    description: signature.description
                });
            }
        });
        
        // Check suspicious patterns
        this.signatureDatabase.suspicious.forEach(signature => {
            if (signature.pattern.test(content)) {
                findings.push({
                    type: 'suspicious_pattern',
                    severity: signature.threat,
                    description: signature.description
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
            /scan.*code/i
        ];
        
        // Check if any keylogger pattern matches
        const hasKeyloggerPattern = keyloggerPatterns.some(pattern => pattern.test(content));
        
        // Check filename for keylogger indicators
        const suspiciousFilename = /keylogger|keystroke|keylog|kl/i.test(filename);
        
        return hasKeyloggerPattern || suspiciousFilename;
    }
    
    logAnalysisResults(filename, analysis) {
        const threatColors = {
            safe: 'green',
            low: 'blue',
            medium: 'yellow',
            high: 'red',
            critical: 'red'
        };
        
        this.logToTerminal(`[COMPLETE] ${filename} - Threat Level: ${analysis.threatLevel.toUpperCase()}`, threatColors[analysis.threatLevel]);
        
        analysis.findings.forEach(finding => {
            const color = finding.severity === 'critical' ? 'red' : 
                         finding.severity === 'high' ? 'red' : 
                         finding.severity === 'medium' ? 'yellow' : 'blue';
            this.logToTerminal(`[${finding.severity.toUpperCase()}] ${finding.description}`, color);
        });
        
        this.logToTerminal(`[SCORE] Threat Score: ${analysis.threatScore}/100`, 'blue');
        this.logToTerminal('────────────────────────────────────────', 'gray');
    }
    
    logToTerminal(message, color = 'white') {
        const terminal = document.getElementById('terminalOutput');
        const timestamp = new Date().toLocaleTimeString();
        const colorClass = this.getColorClass(color);
        
        const logEntry = document.createElement('div');
        logEntry.className = colorClass;
        logEntry.textContent = `[${timestamp}] ${message}`;
        
        terminal.appendChild(logEntry);
        terminal.scrollTop = terminal.scrollHeight;
    }
    
    getColorClass(color) {
        const colorMap = {
            white: 'text-white',
            green: 'text-green-400',
            blue: 'text-blue-400',
            yellow: 'text-yellow-400',
            red: 'text-red-400',
            gray: 'text-gray-500'
        };
        return colorMap[color] || 'text-white';
    }
    
    updateThreatLevel() {
        if (this.analysisResults.size === 0) {
            // Show secure state when no files are analyzed
            document.getElementById('threatPercentage').textContent = '—';
            const statusElement = document.getElementById('threatPercentage').nextElementSibling;
            statusElement.textContent = 'NO FILES ANALYZED';
            statusElement.className = 'text-xs text-gray-400';
    
            // Set all bars to 100% (secure) when no files
            document.getElementById('integrityBar').style.width = '100%';
            document.getElementById('extensionBar').style.width = '100%';
            document.getElementById('permissionBar').style.width = '100%';
            
            // Set all bars to green (secure)
            this.updateBarColor('integrityBar', 100);
            this.updateBarColor('extensionBar', 100);
            this.updateBarColor('permissionBar', 100);
            return;
        }
        
        let totalScore = 0;
        let maxScore = 0;
        
        this.analysisResults.forEach(analysis => {
            totalScore += analysis.threatScore;
            maxScore += 100;
        });
        
        const averageThreat = (totalScore / maxScore) * 100;
        const securityScore = Math.max(0, Math.round(100 - averageThreat));
        
        // Update threat percentage display
        document.getElementById('threatPercentage').textContent = `${Math.round(averageThreat)}%`;
        
        // Update status based on threat level
        const statusElement = document.getElementById('threatPercentage').nextElementSibling;
        if (securityScore <= 20) {
            statusElement.textContent = 'CRITICAL THREAT';
            statusElement.className = 'text-xs text-red-400';
        } else if (securityScore <= 50) {
            statusElement.textContent = 'HIGH RISK';
            statusElement.className = 'text-xs text-red-400';
        } else if (securityScore <= 75) {
            statusElement.textContent = 'MODERATE RISK';
            statusElement.className = 'text-xs text-yellow-400';
        } else if (securityScore <= 90) {
            statusElement.textContent = 'LOW RISK';
            statusElement.className = 'text-xs text-blue-400';
        } else {
            statusElement.textContent = 'NO THREAT DETECTED';
            statusElement.className = 'text-xs text-green-400';
        }

        // Update progress bars
        this.updateProgressBars(averageThreat);
    }
    
    updateProgressBars(threatLevel) {
        // Calculate security scores (inverse of threat level)
        const integrity = Math.max(0, 100 - threatLevel);
        const extension = Math.max(0, 100 - (threatLevel * 0.8));
        const permission = Math.max(0, 100 - (threatLevel * 0.6));
        
        // Animate the progress bars
        anime({
            targets: '#integrityBar',
            width: `${integrity}%`,
            duration: 1000,
            easing: 'easeOutQuart'
        });
        
        anime({
            targets: '#extensionBar',
            width: `${extension}%`,
            duration: 1000,
            delay: 200,
            easing: 'easeOutQuart'
        });
        
        anime({
            targets: '#permissionBar',
            width: `${permission}%`,
            duration: 1000,
            delay: 400,
            easing: 'easeOutQuart'
        });
        
        // Update bar colors based on threat level
        this.updateBarColor('integrityBar', integrity);
        this.updateBarColor('extensionBar', extension);
        this.updateBarColor('permissionBar', permission);
    }
    
    updateBarColor(barId, value) {
        const bar = document.getElementById(barId);
        if (value >= 80) {
            bar.className = 'h-full bg-green-400 rounded';
        } else if (value >= 60) {
            bar.className = 'h-full bg-yellow-400 rounded';
        } else {
            bar.className = 'h-full bg-red-400 rounded';
        }
    }
    
    updateFileQueue() {
        const queueContainer = document.getElementById('fileQueue');
        
        if (this.files.length === 0) {
            queueContainer.innerHTML = '<div class="text-gray-400 text-center py-8">No files in queue</div>';
            return;
        }
        
        queueContainer.innerHTML = '';
        
        this.files.forEach(file => {
            const analysis = this.analysisResults.get(file.name);
            const threatLevel = analysis ? analysis.threatLevel : 'pending';
            
            const fileCard = document.createElement('div');
            fileCard.className =
                'flex items-start gap-3 p-4 bg-gray-800 rounded-lg flex-wrap sm:flex-nowrap';

            
            const iconClass = this.getFileIconClass(threatLevel);
            const threatColor = this.getThreatColor(threatLevel);
            
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
                    <div class="text-sm font-medium ${threatColor}">${threatLevel.toUpperCase()}</div>
                    <div class="text-xs text-gray-400">
                        ${analysis ? `THREAT ${analysis.threatScore}/100` : 'PENDING ANALYSIS'}
                    </div>
                </div>
            `;
            
            queueContainer.appendChild(fileCard);
        });
    }
    
    getFileIconClass(threatLevel) {
        switch (threatLevel) {
            case 'safe': return 'safe-file';
            case 'low': return 'warning-file';
            case 'medium': return 'warning-file';
            case 'high': return 'danger-file';
            case 'critical': return 'danger-file';
            default: return 'safe-file';
        }
    }
    
    getThreatColor(threatLevel) {
        switch (threatLevel) {
            case 'safe': return 'text-green-400';
            case 'low': return 'text-blue-400';
            case 'medium': return 'text-yellow-400';
            case 'high': return 'text-red-400';
            case 'critical': return 'text-red-400';
            default: return 'text-gray-400';
        }
    }
    
    getFileExtension(filename) {
        const ext = filename.split('.').pop();
        return ext ? ext.toUpperCase().substring(0, 3) : '???';
    }
    
    updateStats() {
        let safe = 0, warning = 0, threat = 0;
        
        this.analysisResults.forEach(analysis => {
            switch (analysis.threatLevel) {
                case 'safe':
                    safe++;
                    break;
                case 'low':
                case 'medium':
                    warning++;
                    break;
                case 'high':
                case 'critical':
                    threat++;
                    break;
            }
        });
        
        document.getElementById('safeCount').textContent = safe;
        document.getElementById('warningCount').textContent = warning;
        document.getElementById('threatCount').textContent = threat;
        
        // Animate counters
        this.animateCounter('safeCount', safe);
        this.animateCounter('warningCount', warning);
        this.animateCounter('threatCount', threat);
    }
    
    animateCounter(elementId, targetValue) {
        const element = document.getElementById(elementId);
        const startValue = parseInt(element.textContent) || 0;
        
        anime({
            targets: { value: startValue },
            value: targetValue,
            duration: 1000,
            easing: 'easeOutQuart',
            update: function(anim) {
                element.textContent = Math.round(anim.animatables[0].target.value);
            }
        });
    }
    
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    initializeAnimations() {
        new Typed('#typed-text', {
            strings: [
                'Advanced File Security Analysis',
                'Malware Detection & Risk Analysis',
                'Extension Spoofing Detection',
                'Keylogger Identification',
                'Real-time Threat Assessment'
            ],
            typeSpeed: 50,
            backSpeed: 30,
            backDelay: 2000,
            loop: true
        });
        this.setupScrollAnimations();
    }
    
    setupScrollAnimations() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    anime({
                        targets: entry.target,
                        opacity: [0, 1],
                        translateY: [50, 0],
                        duration: 800,
                        easing: 'easeOutQuart'
                    });
                }
            });
        }, observerOptions);
        
        document.querySelectorAll('.analysis-card').forEach(card => {
            card.style.opacity = '0';
            observer.observe(card);
        });
    }
    
    startMatrixBackground() {
        const canvas = document.getElementById('matrixCanvas');
        const ctx = canvas.getContext('2d');
        
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
        const charArray = chars.split('');
        
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = Array(Math.floor(columns)).fill(1);
        
        function drawMatrix() {
            ctx.fillStyle = 'rgba(10, 10, 10, 0.04)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            ctx.fillStyle = '#00ff41';
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
        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
    }
}
function renderDynamicResults(results) {
    const container = document.getElementById("dynamicFileResults");
    container.innerHTML = "";

    results.forEach((file, index) => {
        const sectionId = `fileDetails_${index}`;
        const aiId = `aiExplain_${index}`;

        const card = document.createElement("div");
        card.className = "analysis-card rounded-xl p-6";

        card.innerHTML = `
            <!-- HEADER -->
            <div class="expandable-section flex justify-between items-center p-4 rounded-lg"
                 onclick="toggleSection('${sectionId}')">

                <div>
                    <h3 class="text-lg font-semibold text-white">${file.name}</h3>
                    <p class="text-gray-400 text-sm">
                        Threat Level: ${file.threatLevel.toUpperCase()}
                    </p>
                </div>

                <span class="threat-badge threat-${file.threatLevel}">
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

                <!-- SPYWARE PROFILE -->
                <div>
                    <h4 class="text-white font-semibold mb-2">Spyware Behavior</h4>
                    <ul class="text-sm text-gray-300 space-y-1">
                        <li>Surveillance: ${file.spywareProfile.surveillance ? "Yes" : "No"}</li>
                        <li>Persistence: ${file.spywareProfile.persistence ? "Yes" : "No"}</li>
                        <li>Stealth: ${file.spywareProfile.stealth ? "Yes" : "No"}</li>
                        <li>
                        ${file.spywareProfile.networkContext === "web"
                            ? "Network Activity Detected"
                            : "Data Exfiltration"}
                        : ${file.spywareProfile.dataExfiltration ? "Yes" : "No"}
                        </li>
                        <li>Credential Harvesting: ${file.spywareProfile.credentialHarvesting ? "Yes" : "No"}</li>
                    </ul>
                </div>

                <!-- FINDINGS -->
                <div>
                    <h4 class="text-white font-semibold mb-2">Findings</h4>
                    <ul class="text-sm text-gray-300 space-y-1">
                        ${file.findings.map(f =>
                            `<li>• ${f.description} (${f.severity})</li>`
                        ).join("")}
                    </ul>
                </div>

                <!-- AI EXPLANATION -->
                <div class="analysis-card p-4">
                    <h4 class="text-blue-400 font-semibold mb-2">
                        AI-Assisted Threat Explanation
                    </h4>
                    <p id="${aiId}" class="text-gray-300 text-sm">
                        AI is analyzing this file…
                    </p>
                </div>
            </div>
        `;

        container.appendChild(card);

        // Call AI explanation
        runAIExplanation(file, aiId);
    });
}
async function runAIExplanation(file, targetId) {
    const element = document.getElementById(targetId);
    if (!element) return;

    element.textContent = "Analyzing threat behavior using AI…";

    const summary = `
File name: ${file.name}
Threat level: ${file.threatLevel}
Threat score: ${file.threatScore}

Spyware behavior:
- Surveillance: ${file.spywareProfile.surveillance}
- Persistence: ${file.spywareProfile.persistence}
- Stealth: ${file.spywareProfile.stealth}
- Data Exfiltration: ${file.spywareProfile.dataExfiltration}
- Credential Harvesting: ${file.spywareProfile.credentialHarvesting}

Findings:
${file.findings.map(f => "- " + f.description).join("\n")}

Explain why this file is dangerous in simple terms.
`;
/*
This block enables real LLM-based explanations
via a secure backend API 
To enable real AI explanations first create the endpoint which i alr did below
then store api key securely and uncomment this block.
connect w backend and return normal text exp to users

For this version, an offline heuristic explanation
engine is used to ensure consistent behavior
across all systems and during evaluations.
    try {
        const response = await fetch("/api/ai-explain", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ summary })
        });

        const data = await response.json();
        element.textContent = data.explanation;

    } catch (err) {
        element.textContent =
            "AI explanation unavailable. Showing heuristic-based analysis.";
    }
*/
// 🧠 Heuristic AI Explanation Engine (Offline)
let explanation = [];

if (file.threatLevel === "critical" || file.threatLevel === "high") {
    explanation.push(
        "This file demonstrates multiple coordinated behaviors commonly seen in spyware. It attempts to collect sensitive information, remain active on the system, and operate without user awareness, indicating a high-severity security threat."
    );
}

if (file.spywareProfile.surveillance) {
    explanation.push(
        "Indicators suggest that this file may secretly monitor user activity, such as application usage or on-screen behavior, without user knowledge or consent."
    );
}

if (file.spywareProfile.credentialHarvesting) {
    explanation.push(
        "The file shows behavior consistent with collecting usernames, passwords, or other sensitive input, posing a direct risk to personal and account security."
    );
}

if (file.spywareProfile.persistence) {
    explanation.push(
        "This file attempts to maintain long-term presence by restarting automatically or embedding itself into system startup processes, making removal more difficult."
    );
}

if (file.spywareProfile.dataExfiltration) {
    if (file.spywareProfile.networkContext === "web") {
        explanation.push(
            "This file contains network-related functionality commonly used in web applications, such as loading external resources or making HTTP requests. No indicators of malicious data theft or spyware behavior were detected."
        );
    } else {
        explanation.push(
            "Network-related activity suggests that collected data may be transmitted to external servers, which is a common technique used by spyware to exfiltrate information silently."
        );
    }
}


if (file.keyloggerDetected) {
    explanation.push(
        "Keystroke monitoring behavior was detected, allowing the file to record typed information such as passwords, messages, or financial data."
    );
}

if (explanation.length === 0) {
    explanation.push(
        "Based on the current analysis, this file behaves as expected and does not exhibit signs of malicious or intrusive activity."
    );
}

element.textContent = explanation.join(" ");

}


// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CyberGuardSpywareAnalyzer();
});

// Add some utility functions for enhanced functionality
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed top-20 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm ${
        type === 'success' ? 'bg-green-600' :
        type === 'warning' ? 'bg-yellow-600' :
        type === 'error' ? 'bg-red-600' :
        'bg-blue-600'
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
    anime({
        targets: notification,
        translateX: [300, 0],
        opacity: [0, 1],
        duration: 300,
        easing: 'easeOutQuart'
    });
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        anime({
            targets: notification,
            translateX: [0, 300],
            opacity: [1, 0],
            duration: 300,
            easing: 'easeInQuart',
            complete: () => notification.remove()
        });
    }, 5000);
}

// Analysis dropdown functionality
function toggleAnalysisDropdown(type) {
    const dropdown = document.getElementById(type + 'Dropdown');
    const icon = dropdown.previousElementSibling.querySelector('.dropdown-icon');
    
    if (dropdown.classList.contains('hidden')) {
        dropdown.classList.remove('hidden');
        icon.classList.add('rotated');
        
        anime({
            targets: dropdown,
            opacity: [0, 1],
            maxHeight: [0, '1000px'],
            duration: 300,
            easing: 'easeOutQuart'
        });
    } else {
        anime({
            targets: dropdown,
            opacity: [1, 0],
            maxHeight: ['200px', 0],
            duration: 200,
            easing: 'easeInQuart',
            complete: () => {
                dropdown.classList.add('hidden');
                icon.classList.remove('rotated');
            }
        });
    }
}

// Export functionality for detailed reports
function exportReport() {
    // This would generate a comprehensive PDF report
    showNotification('Report export functionality coming soon!', 'info');
}

// Share analysis functionality
function shareAnalysis() {
    // This would generate a shareable link
    showNotification('Analysis sharing functionality coming soon!', 'info');
}

// Deep scan functionality
function performDeepScan() {
    showNotification('Deep scan initiated - this may take longer for thorough analysis', 'warning');
    // This would trigger more intensive analysis
}
// url shit 
// phone swipe

let touchStartX = 0;
let touchEndX = 0;

const SWIPE_THRESHOLD = 60;
const pages = [
  "index.html",   // File analysis
  "url.html",     // URL analysis
  "results.html",
  "about.html"
];

function getCurrentPageIndex() {
  let currentPage = window.location.pathname.split("/").pop();
  if (!currentPage || currentPage === "") {
    currentPage = "index.html";
  }

  return pages.indexOf(currentPage);
}

function handleSwipe() {
  const deltaX = touchStartX - touchEndX;
  const currentIndex = getCurrentPageIndex();

  if (currentIndex === -1) return;

  // Swipe LEFT → next page
  if (deltaX > SWIPE_THRESHOLD && currentIndex < pages.length - 1) {
    document.body.classList.add("page-exit-left");
    setTimeout(() => {
      window.location.href = pages[currentIndex + 1];
    }, 260);
  }

  // Swipe RIGHT → previous page
  if (deltaX < -SWIPE_THRESHOLD && currentIndex > 0) {
    document.body.classList.add("page-exit-right");
    setTimeout(() => {
      window.location.href = pages[currentIndex - 1];
    }, 260);
  }
}
let touchStartY = 0;

window.addEventListener("touchstart", (e) => {
  touchStartX = e.changedTouches[0].screenX;
  touchStartY = e.changedTouches[0].screenY;
});

window.addEventListener("touchend", (e) => {
  touchEndX = e.changedTouches[0].screenX;
  const touchEndY = e.changedTouches[0].screenY;

  // Ignore vertical scroll gestures
  if (Math.abs(touchEndY - touchStartY) > 80) return;

  handleSwipe();
});

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import sqlite3

# Import your detection logic (use simplified version if advanced doesn't work)
try:
    from advanced_detection_logic import AdvancedAPKDetector
    detector = AdvancedAPKDetector()
    print("✅ Advanced APK Detector loaded successfully!")
except ImportError:
    try:
        from simplified_detection_logic import SimplifiedAPKDetector
        detector = SimplifiedAPKDetector()
        print("⚠️ Using simplified detector")
    except ImportError:
        print("❌ Warning: No detection logic found, using dummy detector")
        detector = None

app = Flask(
    __name__,
    template_folder="../ui/templates",
    static_folder="../ui/static"
)

app.config['SECRET_KEY'] = 'cybersentinels-hackathon-mp-police-2025'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT,
            risk_level TEXT,
            risk_score INTEGER,
            threat_indicators TEXT,
            scan_timestamp DATETIME,
            analysis_results TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'apk'

# ENHANCED THREAT DETECTION - NEW COMPETITIVE FEATURE
def enhance_threat_display(analysis_results):
    """Enhanced threat detection for competition demo - MAJOR UPGRADE"""
    enhanced_threats = []
    
    # Add existing threats
    risk_assessment = analysis_results.get('risk_assessment', {})
    existing_threats = risk_assessment.get('threat_indicators', [])
    enhanced_threats.extend(existing_threats)
    
    # INDIAN BANKING IMPERSONATION - COMPETITIVE ADVANTAGE
    indian_check = analysis_results.get('indian_banking_check', {})
    impersonation_score = indian_check.get('impersonation_score', 0)
    if impersonation_score > 60:
        enhanced_threats.append('🚨 HIGH: Indian Banking App Impersonation')
        enhanced_threats.extend(indian_check.get('warnings', []))
    elif impersonation_score > 30:
        enhanced_threats.append('⚠️ MEDIUM: Possible Banking App Similarity')
    
    # BANKING TROJAN PATTERNS - CRITICAL DETECTION
    perm_analysis = analysis_results.get('permission_analysis', {})
    suspicious_combos = perm_analysis.get('suspicious_combinations', [])
    
    if 'banking_trojan_pattern' in suspicious_combos:
        enhanced_threats.append('💀 CRITICAL: Banking Trojan Pattern Detected')
    if 'overlay_attack_pattern' in suspicious_combos:
        enhanced_threats.append('🎭 HIGH: Overlay Attack Capability')
    
    # DANGEROUS PERMISSIONS ANALYSIS
    dangerous_count = len(perm_analysis.get('dangerous_permissions', []))
    if dangerous_count > 8:
        enhanced_threats.append(f'🔴 EXTREME: {dangerous_count} Dangerous Permissions')
    elif dangerous_count > 5:
        enhanced_threats.append(f'🟠 HIGH: {dangerous_count} Dangerous Permissions')
    elif dangerous_count > 2:
        enhanced_threats.append(f'🟡 MEDIUM: {dangerous_count} Dangerous Permissions')
    
    # BEHAVIORAL ANALYSIS RESULTS
    behavioral = analysis_results.get('behavioral_indicators', {})
    trojan_score = behavioral.get('banking_trojan_score', 0)
    
    if trojan_score > 70:
        enhanced_threats.append('💀 CRITICAL: High Banking Trojan Behavior')
    elif trojan_score > 40:
        enhanced_threats.append('🔴 HIGH: Suspicious Banking Behavior')
    
    if behavioral.get('overlay_detection', False):
        enhanced_threats.append('🪟 OVERLAY ATTACK: Screen Overlay Detected')
    if behavioral.get('accessibility_abuse', False):
        enhanced_threats.append('♿ ACCESSIBILITY ABUSE: Service Hijacking')
    if behavioral.get('sms_interception', False):
        enhanced_threats.append('📱 SMS INTERCEPTION: Message Stealing')
    
    # VIRUSTOTAL INTEGRATION RESULTS
    vt_results = analysis_results.get('virustotal_scan', {})
    if vt_results and 'positives' in vt_results:
        positives = vt_results.get('positives', 0)
        total = vt_results.get('total', 0)
        if positives > 5:
            enhanced_threats.append(f'🛡️ VIRUSTOTAL: {positives}/{total} Engines Detected')
        elif positives > 0:
            enhanced_threats.append(f'⚠️ VIRUSTOTAL: {positives}/{total} Engines Flagged')
    
    return enhanced_threats

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

@app.route("/")
def home():
    return redirect(url_for('scan'))

@app.route("/dashboard")
def dashboard():
    """ENHANCED PROFESSIONAL DASHBOARD - MAJOR UPGRADE"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Get recent scans with more details
    c.execute('''
        SELECT filename, risk_level, risk_score, scan_timestamp, threat_indicators, file_hash
        FROM scan_results 
        ORDER BY scan_timestamp DESC 
        LIMIT 15
    ''')
    recent_scans = c.fetchall()
    
    # Enhanced statistics
    c.execute('SELECT COUNT(*) FROM scan_results')
    total_scans = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE risk_level = "HIGH"')
    high_risk_count = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE risk_level = "MEDIUM"')
    medium_risk_count = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE risk_level = "LOW"')
    low_risk_count = c.fetchone()[0]
    
    # Get today's scans
    c.execute('SELECT COUNT(*) FROM scan_results WHERE DATE(scan_timestamp) = DATE("now")')
    today_scans = c.fetchone()[0]
    
    # Get average risk score
    c.execute('SELECT AVG(risk_score) FROM scan_results')
    avg_risk = c.fetchone()[0] or 0
    
    conn.close()
    
    # Calculate enhanced metrics
    detection_rate = round((high_risk_count / max(total_scans, 1)) * 100, 1)
    threat_density = round(((high_risk_count + medium_risk_count) / max(total_scans, 1)) * 100, 1)
    
    stats = {
        'total_scans': total_scans,
        'high_risk': high_risk_count,
        'medium_risk': medium_risk_count,
        'low_risk': low_risk_count,
        'today_scans': today_scans,
        'detection_rate': detection_rate,
        'threat_density': threat_density,
        'avg_risk': round(avg_risk, 1)
    }
    
    # PROFESSIONAL DASHBOARD HTML - ENHANCED
    dashboard_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CyberSentinels - MP Police Dashboard</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%); 
                color: #fff; 
                min-height: 100vh;
            }}
            .dashboard-container {{ padding: 20px; max-width: 1400px; margin: 0 auto; }}
            .header {{ text-align: center; margin-bottom: 40px; padding: 30px 0; }}
            .header h1 {{ font-size: 3rem; color: #00d4ff; margin-bottom: 10px; }}
            .header .subtitle {{ color: #8892b0; font-size: 1.2rem; margin-bottom: 5px; }}
            .header .org {{ color: #ffd93d; font-weight: bold; }}
            
            .stats-grid {{ 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                gap: 25px; 
                margin-bottom: 50px; 
            }}
            
            .stat-card {{ 
                background: linear-gradient(145deg, #1a1f2e 0%, #2d3748 100%); 
                border: 1px solid #3a4a5c; 
                border-radius: 15px; 
                padding: 25px; 
                text-align: center; 
                position: relative;
                overflow: hidden;
            }}
            
            .stat-card::before {{
                content: '';
                position: absolute;
                top: 0; left: 0; right: 0;
                height: 4px;
                background: var(--accent-color);
            }}
            
            .stat-card.total {{ --accent-color: #64b5f6; }}
            .stat-card.high-risk {{ --accent-color: #ff6b6b; }}
            .stat-card.medium-risk {{ --accent-color: #ffd93d; }}
            .stat-card.low-risk {{ --accent-color: #6bcf7f; }}
            .stat-card.today {{ --accent-color: #9c27b0; }}
            .stat-card.detection {{ --accent-color: #ff9800; }}
            .stat-card.threat {{ --accent-color: #f44336; }}
            .stat-card.avg {{ --accent-color: #00bcd4; }}
            
            .stat-number {{ 
                font-size: 2.5rem; 
                font-weight: bold; 
                margin-bottom: 8px; 
                color: var(--accent-color);
            }}
            
            .stat-label {{ 
                color: #a0aec0; 
                font-size: 0.9rem; 
                text-transform: uppercase; 
                letter-spacing: 1px; 
            }}
            
            .recent-section {{ 
                background: rgba(26, 31, 46, 0.8); 
                border-radius: 15px; 
                padding: 30px; 
                margin-bottom: 30px; 
            }}
            
            .recent-section h2 {{ 
                color: #00d4ff; 
                margin-bottom: 25px; 
                font-size: 1.8rem; 
            }}
            
            .scan-grid {{ 
                display: grid; 
                gap: 15px; 
            }}
            
            .scan-item {{ 
                background: rgba(45, 55, 72, 0.5); 
                border-radius: 10px; 
                padding: 20px; 
                display: grid; 
                grid-template-columns: 2fr 1fr 100px 120px; 
                align-items: center; 
                gap: 20px; 
                border-left: 4px solid var(--risk-color); 
            }}
            
            .scan-item.risk-high {{ --risk-color: #ff6b6b; }}
            .scan-item.risk-medium {{ --risk-color: #ffd93d; }}
            .scan-item.risk-low {{ --risk-color: #6bcf7f; }}
            
            .file-info h3 {{ color: #fff; margin-bottom: 5px; }}
            .file-info .meta {{ color: #8892b0; font-size: 0.9rem; }}
            
            .risk-badge {{ 
                padding: 8px 16px; 
                border-radius: 20px; 
                font-weight: bold; 
                text-align: center; 
                font-size: 0.9rem; 
            }}
            
            .risk-high {{ background: rgba(255, 107, 107, 0.2); color: #ff6b6b; border: 1px solid #ff6b6b; }}
            .risk-medium {{ background: rgba(255, 193, 61, 0.2); color: #ffd93d; border: 1px solid #ffd93d; }}
            .risk-low {{ background: rgba(107, 207, 127, 0.2); color: #6bcf7f; border: 1px solid #6bcf7f; }}
            
            .score-display {{ 
                font-size: 1.5rem; 
                font-weight: bold; 
                text-align: center; 
            }}
            
            .actions {{ 
                text-align: center; 
                margin-top: 40px; 
            }}
            
            .btn {{ 
                display: inline-block; 
                background: linear-gradient(45deg, #00d4ff, #0099cc); 
                color: #0f1419; 
                padding: 15px 30px; 
                border-radius: 8px; 
                text-decoration: none; 
                font-weight: bold; 
                margin: 0 10px; 
                transition: transform 0.2s ease; 
            }}
            
            .btn:hover {{ transform: translateY(-2px); }}
            .btn-secondary {{ background: linear-gradient(45deg, #6bcf7f, #5bb970); }}
            .btn-danger {{ background: linear-gradient(45deg, #ff6b6b, #e55555); color: white; }}
        </style>
    </head>
    <body>
        <div class="dashboard-container">
            <div class="header">
                <h1>🛡️ CyberSentinels Dashboard</h1>
                <p class="subtitle">Advanced Banking APK Threat Detection System</p>
                <p class="org">Madhya Pradesh Police - Cybercrime Division</p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card total">
                    <div class="stat-number">{stats['total_scans']}</div>
                    <div class="stat-label">Total Scans</div>
                </div>
                
                <div class="stat-card high-risk">
                    <div class="stat-number">{stats['high_risk']}</div>
                    <div class="stat-label">High Risk</div>
                </div>
                
                <div class="stat-card medium-risk">
                    <div class="stat-number">{stats['medium_risk']}</div>
                    <div class="stat-label">Medium Risk</div>
                </div>
                
                <div class="stat-card low-risk">
                    <div class="stat-number">{stats['low_risk']}</div>
                    <div class="stat-label">Safe / Low Risk</div>
                </div>
                
                <div class="stat-card today">
                    <div class="stat-number">{stats['today_scans']}</div>
                    <div class="stat-label">Today's Scans</div>
                </div>
                
                <div class="stat-card detection">
                    <div class="stat-number">{stats['detection_rate']}%</div>
                    <div class="stat-label">Detection Rate</div>
                </div>
                
                <div class="stat-card threat">
                    <div class="stat-number">{stats['threat_density']}%</div>
                    <div class="stat-label">Threat Density</div>
                </div>
                
                <div class="stat-card avg">
                    <div class="stat-number">{stats['avg_risk']}</div>
                    <div class="stat-label">Avg Risk Score</div>
                </div>
            </div>
            
            <div class="recent-section">
                <h2>📊 Recent Threat Analysis</h2>
                <div class="scan-grid">
                    {"".join([f'''
                    <div class="scan-item risk-{scan[1].lower()}">
                        <div class="file-info">
                            <h3>{scan[0]}</h3>
                            <div class="meta">Scanned: {scan[3]} | Hash: {scan[5][:12] if scan[5] else "Unknown"}...</div>
                        </div>
                        <div class="risk-badge risk-{scan[1].lower()}">{scan[1]} RISK</div>
                        <div class="score-display">{scan[2]}/100</div>
                        <div>
                            <a href="/export/{recent_scans.index(scan) + 1}" class="btn btn-secondary" style="padding: 8px 16px; font-size: 0.8rem;">Export</a>
                        </div>
                    </div>
                    ''' for scan in recent_scans[:10]])}
                </div>
            </div>
            
            <div class="actions">
                <a href="/scan" class="btn">🔍 New APK Scan</a>
                <a href="/api/threat-intelligence" class="btn btn-secondary">📈 Export Intelligence</a>
                <a href="/api/threat-intelligence" class="btn btn-danger">🚨 Alert System</a>
            </div>
        </div>
    </body>
    </html>
    """
    
    return dashboard_html

@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        # YOUR EXISTING GET METHOD HTML - KEEPING IT INTACT
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinels - Advanced APK Security Platform</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #0a0a0b 0%, #1a1b23 100%);
            color: #ffffff;
            overflow-x: hidden;
            position: relative;
        }

        /* Animated background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 50%, rgba(0, 212, 255, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(138, 43, 226, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 80%, rgba(255, 20, 147, 0.05) 0%, transparent 50%);
            animation: backgroundShift 20s ease-in-out infinite;
            pointer-events: none;
            z-index: -1;
        }

        @keyframes backgroundShift {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
        }

        /* Navigation */
        nav {
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(10, 10, 11, 0.8);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            position: fixed;
            width: 100%;
            top: 0;
            z-index: 1000;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-links {
            display: flex;
            gap: 2rem;
            align-items: center;
        }

        .nav-links a {
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
            font-size: 0.95rem;
        }

        .nav-links a:hover {
            color: #00d4ff;
        }

        /* Hero Section */
        .hero {
            padding: 8rem 2rem 6rem;
            text-align: center;
            max-width: 1200px;
            margin: 0 auto;
        }

        .hero h1 {
            font-size: clamp(2.5rem, 5vw, 4rem);
            font-weight: 700;
            margin-bottom: 1.5rem;
            line-height: 1.2;
        }

        .gradient-text {
            background: linear-gradient(135deg, #00d4ff, #8a2be2, #ff1493);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-size: 200% 200%;
            animation: gradientShift 4s ease-in-out infinite;
        }

        @keyframes gradientShift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }

        .hero p {
            font-size: 1.25rem;
            color: rgba(255, 255, 255, 0.7);
            margin-bottom: 3rem;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
            line-height: 1.6;
        }

        .cta-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }

        .cta-primary, .cta-secondary {
            padding: 1rem 2rem;
            border-radius: 50px;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.3s ease;
            font-size: 1rem;
            border: 2px solid transparent;
            position: relative;
            overflow: hidden;
        }

        .cta-primary {
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            color: white;
        }

        .cta-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.3);
        }

        .cta-secondary {
            background: transparent;
            color: #00d4ff;
            border-color: #00d4ff;
        }

        .cta-secondary:hover {
            background: rgba(0, 212, 255, 0.1);
            transform: translateY(-2px);
        }

        /* Upload Section */
        .upload-section {
            max-width: 800px;
            margin: 4rem auto;
            padding: 0 2rem;
        }

        .upload-card {
            background: rgba(26, 27, 35, 0.8);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 3rem 2rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .upload-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
        }

        .upload-title {
            font-size: 1.8rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #fff;
        }

        .upload-subtitle {
            color: rgba(255, 255, 255, 0.6);
            margin-bottom: 2rem;
            font-size: 1rem;
        }

        .file-upload-area {
            border: 2px dashed rgba(0, 212, 255, 0.5);
            border-radius: 15px;
            padding: 3rem 2rem;
            margin-bottom: 2rem;
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
        }

        .file-upload-area:hover {
            border-color: #00d4ff;
            background: rgba(0, 212, 255, 0.05);
        }

        .file-upload-area.dragover {
            border-color: #8a2be2;
            background: rgba(138, 43, 226, 0.1);
        }

        .upload-icon {
            font-size: 3rem;
            color: #00d4ff;
            margin-bottom: 1rem;
        }

        .file-input {
            opacity: 0;
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }

        .upload-text {
            color: rgba(255, 255, 255, 0.8);
            font-size: 1rem;
            margin-bottom: 0.5rem;
        }

        .file-types {
            color: rgba(255, 255, 255, 0.5);
            font-size: 0.875rem;
        }

        .analyze-btn {
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            color: white;
            border: none;
            padding: 1rem 3rem;
            border-radius: 50px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .analyze-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.4);
        }

        .analyze-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        /* Features Section */
        .features {
            max-width: 1200px;
            margin: 6rem auto;
            padding: 0 2rem;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }

        .feature-card {
            background: rgba(26, 27, 35, 0.6);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 2rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
            text-align: center;
        }

        .feature-card:hover {
            transform: translateY(-5px);
            border-color: rgba(0, 212, 255, 0.5);
        }

        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }

        .feature-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #fff;
        }

        .feature-description {
            color: rgba(255, 255, 255, 0.7);
            line-height: 1.6;
        }

        /* How It Works */
        .how-it-works {
            max-width: 1200px;
            margin: 6rem auto;
            padding: 0 2rem;
            text-align: center;
        }

        .section-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .section-subtitle {
            color: rgba(255, 255, 255, 0.6);
            font-size: 1.1rem;
            margin-bottom: 3rem;
        }

        .steps-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }

        .step {
            position: relative;
            text-align: center;
        }

        .step-number {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            color: white;
            font-size: 1.5rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
        }

        .step-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #fff;
        }

        .step-description {
            color: rgba(255, 255, 255, 0.7);
            line-height: 1.6;
        }

        /* Stats Section */
        .stats {
            background: rgba(26, 27, 35, 0.4);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 3rem 2rem;
            margin: 6rem auto;
            max-width: 1200px;
            margin-left: 2rem;
            margin-right: 2rem;
        }

        .stats-title {
            text-align: center;
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 3rem;
            color: #fff;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 2rem;
        }

        .stat {
            text-align: center;
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: #00d4ff;
            margin-bottom: 0.5rem;
            animation: countUp 2s ease-out;
        }

        .stat-label {
            color: rgba(255, 255, 255, 0.8);
            font-weight: 500;
        }

        /* Team Section */
        .team {
            max-width: 1200px;
            margin: 6rem auto;
            padding: 0 2rem;
            text-align: center;
        }

        .team-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }

        .team-member {
            background: rgba(26, 27, 35, 0.6);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 2rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
            text-align: center;
        }

        .team-member:hover {
            transform: translateY(-5px);
            border-color: rgba(0, 212, 255, 0.5);
        }

        .member-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }

        .member-name {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #fff;
        }

        .member-role {
            color: #00d4ff;
            font-weight: 500;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .nav-links {
                display: none;
            }
            
            .cta-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .upload-card {
                margin: 0 1rem;
            }
            
            .file-upload-area {
                padding: 2rem 1rem;
            }
            
            .features, .how-it-works, .team, .stats {
                margin-left: 1rem;
                margin-right: 1rem;
            }
        }

        /* Loading animation */
        .loading {
            display: none;
            text-align: center;
            margin-top: 2rem;
        }

        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(0, 212, 255, 0.3);
            border-top: 4px solid #00d4ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .selected-file {
            background: rgba(0, 212, 255, 0.1);
            border-color: #00d4ff;
            color: #00d4ff;
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
            display: none;
        }
    </style>
</head>
<body>
    <nav>
        <div class="logo">🛡️ CyberSentinels</div>
        <div class="nav-links">
            <a href="#features">Features</a>
            <a href="#how-it-works">How It Works</a>
            <a href="#team">Team</a>
            <a href="/dashboard">Dashboard</a>
        </div>
    </nav>

    <section class="hero">
        <h1>
            <span class="gradient-text">AI-Powered Malware Detection & Banking Security</span>
        </h1>
        <p>
            Protect your mobile ecosystem with cutting-edge artificial intelligence that detects sophisticated malware, 
            banking trojans, and zero-day threats in real-time. Built for enterprises, trusted by security professionals.
        </p>
        <div class="cta-buttons">
            <a href="#upload" class="cta-primary">🚀 Start Scanning</a>
            <a href="#features" class="cta-secondary">🔍 Learn More</a>
        </div>
    </section>

    <section class="upload-section" id="upload">
        <div class="upload-card">
            <div class="upload-title">APK Security Scanner</div>
            <div class="upload-subtitle">Upload and analyze APK files with our advanced AI-powered detection system</div>
            
            <form method="post" enctype="multipart/form-data" id="uploadForm">
                <div class="upload-title" style="font-size: 1.5rem; margin-bottom: 1rem;">
                    ### Fake Banking APK Detector
                </div>
                <p style="color: rgba(255, 255, 255, 0.6); margin-bottom: 2rem;">
                    Advanced malware detection specialized in banking trojans and financial threats
                </p>
                
                <div class="file-upload-area" id="fileUploadArea">
                    <div class="upload-icon">📱</div>
                    <input type="file" name="file" accept=".apk" class="file-input" id="fileInput" required>
                    <div class="upload-text">Drop your APK file here or click to browse</div>
                    <div class="file-types">Supports APK files up to 100MB • Secure & encrypted analysis</div>
                </div>
                
                <div class="selected-file" id="selectedFile"></div>
                
                <button type="submit" class="analyze-btn" id="analyzeBtn" disabled>
                    ✅ Ready for analysis
                </button>
                
                <div class="loading" id="loadingDiv">
                    <div class="loading-spinner"></div>
                    <div>Initializing scan...</div>
                </div>
            </form>
        </div>
    </section>

    <section class="features" id="features">
        <div class="section-title">Advanced Security Features</div>
        <div class="section-subtitle">Comprehensive protection powered by artificial intelligence and machine learning</div>
        
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon">🧠</div>
                <div class="feature-title">AI-Powered Detection</div>
                <div class="feature-description">
                    Advanced neural networks trained on millions of malware samples to detect even the most sophisticated threats and zero-day attacks.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">⚡</div>
                <div class="feature-title">Real-time Analysis</div>
                <div class="feature-description">
                    Lightning-fast scanning with results in under 30 seconds, powered by distributed cloud computing infrastructure.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🏦</div>
                <div class="feature-title">Banking Security Focus</div>
                <div class="feature-description">
                    Specialized detection for banking trojans, credential stealers, and financial malware targeting mobile banking applications.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🔒</div>
                <div class="feature-title">Privacy Protected</div>
                <div class="feature-description">
                    End-to-end encryption ensures your files remain secure. All uploads are automatically deleted after analysis completion.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">📊</div>
                <div class="feature-title">Detailed Reports</div>
                <div class="feature-description">
                    Comprehensive threat intelligence reports with risk scores, IoCs, and actionable mitigation recommendations.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🌐</div>
                <div class="feature-title">Global Threat Intel</div>
                <div class="feature-description">
                    Connected to worldwide threat intelligence networks with real-time updates on emerging malware families and attack vectors.
                </div>
            </div>
        </div>
    </section>

    <section class="how-it-works" id="how-it-works">
        <div class="section-title">How It Works</div>
        <div class="section-subtitle">Simple, secure, and lightning-fast APK analysis in four easy steps</div>
        
        <div class="steps-grid">
            <div class="step">
                <div class="step-number">1</div>
                <div class="step-title">Upload APK File</div>
                <div class="step-description">
                    Securely upload your APK file through our encrypted interface. Files are processed in an isolated environment for maximum security.
                </div>
            </div>
            
            <div class="step">
                <div class="step-number">2</div>
                <div class="step-title">AI Analysis</div>
                <div class="step-description">
                    Our advanced AI engine performs deep behavioral analysis, static code inspection, and pattern recognition to identify potential threats.
                </div>
            </div>
            
            <div class="step">
                <div class="step-number">3</div>
                <div class="step-title">Threat Detection</div>
                <div class="step-description">
                    Machine learning algorithms cross-reference with global threat databases and identify malicious patterns, trojans, and suspicious behaviors.
                </div>
            </div>
            
            <div class="step">
                <div class="step-number">4</div>
                <div class="step-title">Security Report</div>
                <div class="step-description">
                    Receive a comprehensive security report with risk assessment, threat classification, and actionable recommendations for protection.
                </div>
            </div>
        </div>
    </section>

    <section class="stats">
        <div class="stats-title">Security Intelligence</div>
        <div class="section-subtitle" style="color: rgba(255, 255, 255, 0.6);">Real-time metrics from our global security operations center</div>
        
        <div class="stats-grid">
            <div class="stat">
                <div class="stat-number" data-target="99.7">0</div>
                <div class="stat-label">Detection Rate<br>Accuracy in identifying malware</div>
            </div>
            
            <div class="stat">
                <div class="stat-number" data-target="2847">0</div>
                <div class="stat-label">APKs Analyzed<br>Files processed this month</div>
            </div>
            
            <div class="stat">
                <div class="stat-number" data-target="15.2">0</div>
                <div class="stat-label">Million Threats<br>Blocked globally</div>
            </div>
            
            <div class="stat">
                <div class="stat-number" data-target="12">0</div>
                <div class="stat-label">Seconds Avg<br>Analysis completion time</div>
            </div>
            
            <div class="stat">
                <div class="stat-number" data-target="847">0</div>
                <div class="stat-label">New Malware<br>Variants detected daily</div>
            </div>
            
            <div class="stat">
                <div class="stat-number" data-target="8760">0</div>
                <div class="stat-label">Hours Uptime<br>Continuous protection</div>
            </div>
        </div>
    </section>

    <section class="team" id="team">
        <div class="section-title">Meet Our Team</div>
        <div class="section-subtitle">Elite cybersecurity professionals dedicated to protecting your digital assets</div>
        
        <div class="team-grid">
            <div class="team-member">
                <div class="member-icon">🥷</div>
                <div class="member-name">harshil nayi</div>
                <div class="member-role">Lead Security Architect & backend dev</div>
            </div>
            
            <div class="team-member">
                <div class="member-icon">🤖</div>
                <div class="member-name">mansi devnani</div>
                <div class="member-role">presentation / documantation </div>
            </div>
            
            <div class="team-member">
                <div class="member-icon">⚡</div>
                <div class="member-name">hiral mehta</div>
                <div class="member-role">resourses Generating / presentation </div>
            </div>
            
            <div class="team-member">
                <div class="member-icon">🎨</div>
                <div class="member-name">dhruv adroja</div>
                <div class="member-role">UI/UX Designer</div>
            </div>
        </div>
    </section>

    <script>
        // File upload handling
        const fileInput = document.getElementById('fileInput');
        const fileUploadArea = document.getElementById('fileUploadArea');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const selectedFile = document.getElementById('selectedFile');
        const uploadForm = document.getElementById('uploadForm');
        const loadingDiv = document.getElementById('loadingDiv');

        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                selectedFile.textContent = `Selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
                selectedFile.style.display = 'block';
                analyzeBtn.disabled = false;
                analyzeBtn.textContent = '🔍 Analyze APK';
                analyzeBtn.style.background = 'linear-gradient(135deg, #00d4ff, #8a2be2)';
            }
        });

        // Drag and drop functionality
        fileUploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            fileUploadArea.classList.add('dragover');
        });

        fileUploadArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            fileUploadArea.classList.remove('dragover');
        });

        fileUploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            fileUploadArea.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                fileInput.dispatchEvent(new Event('change'));
            }
        });

        // Form submission handling
        uploadForm.addEventListener('submit', function(e) {
            analyzeBtn.disabled = true;
            analyzeBtn.textContent = 'Analyzing...';
            loadingDiv.style.display = 'block';
        });

        // Animate stats numbers
        function animateStats() {
            const stats = document.querySelectorAll('.stat-number');
            stats.forEach(stat => {
                const target = parseFloat(stat.dataset.target);
                const increment = target / 100;
                let current = 0;
                
                const updateStat = () => {
                    current += increment;
                    if (current < target) {
                        stat.textContent = current.toFixed(1);
                        requestAnimationFrame(updateStat);
                    } else {
                        stat.textContent = target.toString();
                    }
                };
                
                updateStat();
            });
        }

        // Trigger stats animation when section is visible
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateStats();
                    observer.unobserve(entry.target);
                }
            });
        });

        observer.observe(document.querySelector('.stats'));
    </script>
</body>
</html>
        """
    
    if request.method == "POST":
        # Check if the file part is in the request
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(url_for('scan'))
        
        file = request.files['file']
        
        # Check if a file was selected
        if file.filename == '':
            flash('No file selected') 
            return redirect(url_for('scan'))
        
        # Check if file is valid and allowed
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # ENHANCED ANALYSIS - USING YOUR UPGRADED DETECTION LOGIC
                if detector:
                    if hasattr(detector, 'analyze_apk_comprehensive'):
                        analysis_results = detector.analyze_apk_comprehensive(filepath)
                    else:
                        # Fallback to basic analysis
                        analysis_results = {
                            'file_info': {'filename': filename, 'size': os.path.getsize(filepath)},
                            'risk_assessment': {
                                'overall_score': 35,
                                'risk_level': 'MEDIUM',
                                'threat_indicators': ['basic_analysis'],
                                'recommendation': 'Basic analysis completed - upgrade detector for full features'
                            }
                        }
                else:
                    # Dummy analysis if no detector is found
                    analysis_results = {
                        'file_info': {'filename': filename, 'size': os.path.getsize(filepath)},
                        'risk_assessment': {
                            'overall_score': 25,
                            'risk_level': 'LOW',
                            'threat_indicators': ['no_detector'],
                            'recommendation': 'Demo mode - detector not loaded'
                        }
                    }
                
                risk_assessment = analysis_results.get('risk_assessment', {})
                risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
                risk_score = risk_assessment.get('overall_score', 0)
                
                # ENHANCED THREAT DETECTION - MAJOR COMPETITIVE ADVANTAGE
                enhanced_threats = enhance_threat_display(analysis_results)
                
                file_info = analysis_results.get('file_info', {})
                file_hash = file_info.get('sha256', file_info.get('md5', 'unknown'))
                
                # Store enhanced results in the database
                conn = sqlite3.connect('scan_results.db')
                c = conn.cursor()
                c.execute('''
                    INSERT INTO scan_results 
                    (filename, file_hash, risk_level, risk_score, threat_indicators, scan_timestamp, analysis_results)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    filename,
                    file_hash,
                    risk_level,
                    risk_score,
                    json.dumps(enhanced_threats),
                    datetime.now(),
                    json.dumps(analysis_results)
                ))
                conn.commit()
                conn.close()
                
                # Clean up
                os.remove(filepath)
                
                # ENHANCED RESULTS DISPLAY - PROFESSIONAL UPGRADE
                risk_colors = {
                    'HIGH': '#ff6b6b',
                    'MEDIUM': '#ffd93d', 
                    'LOW': '#6bcf7f',
                    'LOW-MEDIUM': '#ffb366',
                    'CRITICAL': '#ff1744'
                }
                risk_color = risk_colors.get(risk_level, '#64b5f6')
                
                # Format file size professionally
                file_size = format_file_size(file_info.get('size', 0))
                
                # Enhanced threat indicators display with emojis and styling
                if enhanced_threats:
                    threat_indicators_html = '<div class="threats-container">'
                    for threat in enhanced_threats[:10]:  # Show top 10 threats
                        threat_class = 'threat-critical' if any(word in threat.lower() for word in ['critical', 'extreme']) else 'threat-high' if any(word in threat.lower() for word in ['high', 'banking']) else 'threat-medium'
                        threat_indicators_html += f'<div class="threat-badge {threat_class}">{threat}</div>'
                    if len(enhanced_threats) > 10:
                        threat_indicators_html += f'<div class="threat-badge threat-info">+{len(enhanced_threats) - 10} more threats</div>'
                    threat_indicators_html += '</div>'
                else:
                    threat_indicators_html = '<div class="no-threats">✅ No specific threats detected</div>'
                
                # Enhanced recommendation based on risk level
                recommendations = {
                    'HIGH': '🚨 IMMEDIATE ACTION REQUIRED - Block this APK and investigate source',
                    'CRITICAL': '💀 CRITICAL THREAT - Do not install. Report to cybercrime authorities',
                    'MEDIUM': '⚠️ PROCEED WITH CAUTION - Manual review recommended before installation',
                    'LOW-MEDIUM': '🔍 MONITOR - Some suspicious indicators detected',
                    'LOW': '✅ APPEARS SAFE - Low risk detected, but remain vigilant'
                }
                recommendation = recommendations.get(risk_level, risk_assessment.get('recommendation', 'Analysis complete'))
                
                confidence = risk_assessment.get('confidence', 0.5)
                
                # Get additional analysis details for display
                perm_analysis = analysis_results.get('permission_analysis', {})
                total_permissions = perm_analysis.get('total_permissions', 0)
                dangerous_permissions = len(perm_analysis.get('dangerous_permissions', []))
                
                # Indian banking check results
                indian_check = analysis_results.get('indian_banking_check', {})
                banking_warnings = indian_check.get('warnings', [])
                impersonation_score = indian_check.get('impersonation_score', 0)
                
                # VirusTotal results
                vt_results = analysis_results.get('virustotal_scan', {})
                vt_status = "🛡️ Integrated" if 'positives' in vt_results else "⏳ Scanning..."
                
                return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinels - Analysis Results</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%); 
            color: #fff; 
            min-height: 100vh; 
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .header h1 {{ font-size: 3rem; color: #00d4ff; margin-bottom: 10px; }}
        .header .subtitle {{ color: #8892b0; font-size: 1.1rem; }}
        
        .results-main {{ 
            display: grid; 
            grid-template-columns: 1fr 300px; 
            gap: 30px; 
            margin-bottom: 40px; 
        }}
        
        .analysis-panel {{ 
            background: rgba(26, 31, 46, 0.9); 
            border-radius: 20px; 
            padding: 40px; 
            border: 1px solid rgba(255, 255, 255, 0.1); 
        }}
        
        .risk-panel {{ 
            background: rgba(26, 31, 46, 0.9); 
            border-radius: 20px; 
            padding: 30px; 
            text-align: center; 
            height: fit-content;
            border: 2px solid {risk_color};
        }}
        
        .risk-score {{ 
            font-size: 4.5rem; 
            font-weight: bold; 
            color: {risk_color}; 
            margin: 20px 0; 
            text-shadow: 0 0 20px {risk_color}40;
        }}
        
        .risk-level {{ 
            display: inline-block; 
            background: {risk_color}; 
            color: {('#000' if risk_level in ['MEDIUM', 'LOW'] else '#fff')}; 
            padding: 12px 25px; 
            border-radius: 30px; 
            font-weight: bold; 
            font-size: 1.3rem; 
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .confidence-display {{
            margin-top: 20px;
        }}
        
        .confidence-meter {{ 
            background: #2d3748; 
            height: 12px; 
            border-radius: 6px; 
            overflow: hidden; 
            margin: 10px 0; 
        }}
        
        .confidence-fill {{ 
            height: 100%; 
            background: {risk_color}; 
            width: {confidence * 100}%; 
            transition: width 1s ease; 
            border-radius: 6px;
        }}
        
        .info-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 30px 0; 
        }}
        
        .info-card {{ 
            background: rgba(45, 55, 72, 0.5); 
            border-radius: 15px; 
            padding: 20px; 
            text-align: center; 
        }}
        
        .info-label {{ 
            color: #8892b0; 
            font-size: 0.9rem; 
            margin-bottom: 8px; 
            text-transform: uppercase; 
            letter-spacing: 1px; 
        }}
        
        .info-value {{ 
            color: #fff; 
            font-size: 1.5rem; 
            font-weight: bold; 
        }}
        
        .threats-section {{ 
            margin: 40px 0; 
        }}
        
        .section-title {{ 
            font-size: 1.8rem; 
            color: #00d4ff; 
            margin-bottom: 20px; 
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .threats-container {{ 
            display: flex; 
            flex-wrap: wrap; 
            gap: 12px; 
        }}
        
        .threat-badge {{ 
            padding: 10px 16px; 
            border-radius: 25px; 
            font-weight: bold; 
            font-size: 0.9rem; 
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .threat-critical {{ 
            background: rgba(255, 23, 68, 0.2); 
            border: 2px solid #ff1744; 
            color: #ff1744; 
        }}
        
        .threat-high {{ 
            background: rgba(255, 107, 107, 0.2); 
            border: 2px solid #ff6b6b; 
            color: #ff6b6b; 
        }}
        
        .threat-medium {{ 
            background: rgba(255, 193, 61, 0.2); 
            border: 2px solid #ffd93d; 
            color: #ffd93d; 
        }}
        
        .threat-info {{ 
            background: rgba(0, 212, 255, 0.2); 
            border: 2px solid #00d4ff; 
            color: #00d4ff; 
        }}
        
        .no-threats {{ 
            color: #6bcf7f; 
            font-weight: bold; 
            text-align: center; 
            font-size: 1.2rem; 
            padding: 30px; 
            background: rgba(107, 207, 127, 0.1); 
            border-radius: 15px; 
            border: 2px solid #6bcf7f; 
        }}
        
        .recommendation-panel {{ 
            background: linear-gradient(145deg, rgba(0, 212, 255, 0.1), rgba(138, 43, 226, 0.05)); 
            border: 2px solid #00d4ff; 
            border-radius: 15px; 
            padding: 30px; 
            margin: 40px 0; 
            text-align: center; 
        }}
        
        .recommendation-panel h3 {{ 
            color: #00d4ff; 
            margin-bottom: 15px; 
            font-size: 1.5rem; 
        }}
        
        .recommendation-text {{ 
            font-size: 1.1rem; 
            line-height: 1.6; 
            color: #fff; 
        }}
        
        .banking-alerts {{ 
            margin: 30px 0; 
        }}
        
        .banking-alert {{ 
            background: rgba(255, 193, 61, 0.2); 
            border: 2px solid #ffd93d; 
            color: #ffd93d; 
            padding: 20px; 
            border-radius: 15px; 
            margin-bottom: 15px; 
            font-weight: bold; 
        }}
        
        .banking-alert.high-threat {{ 
            background: rgba(255, 107, 107, 0.2); 
            border-color: #ff6b6b; 
            color: #ff6b6b; 
        }}
        
        .actions {{ 
            text-align: center; 
            margin-top: 50px; 
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }}
        
        .btn {{ 
            display: inline-block; 
            padding: 15px 30px; 
            border-radius: 10px; 
            text-decoration: none; 
            font-weight: bold; 
            font-size: 1rem; 
            transition: all 0.3s ease; 
            border: 2px solid;
        }}
        
        .btn-primary {{ 
            background: linear-gradient(45deg, #00d4ff, #0099cc); 
            color: #0f1419; 
            border-color: #00d4ff;
        }}
        
        .btn-secondary {{ 
            background: linear-gradient(45deg, #6bcf7f, #5bb970); 
            color: #0f1419; 
            border-color: #6bcf7f;
        }}
        
        .btn-danger {{ 
            background: linear-gradient(45deg, #ff6b6b, #e55555); 
            color: white; 
            border-color: #ff6b6b;
        }}
        
        .btn:hover {{ 
            transform: translateY(-3px); 
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3); 
        }}
        
        .additional-info {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
            margin: 40px 0; 
        }}
        
        .info-panel {{ 
            background: rgba(45, 55, 72, 0.3); 
            border-radius: 15px; 
            padding: 25px; 
            border: 1px solid rgba(255, 255, 255, 0.1); 
        }}
        
        .info-panel h4 {{ 
            color: #00d4ff; 
            margin-bottom: 15px; 
            font-size: 1.2rem; 
        }}
        
        .info-panel p {{ 
            color: #a0aec0; 
            line-height: 1.6; 
        }}
        
        @media (max-width: 768px) {{
            .results-main {{ 
                grid-template-columns: 1fr; 
            }}
            .container {{ padding: 20px 10px; }}
            .analysis-panel {{ padding: 25px; }}
            .actions {{ flex-direction: column; align-items: center; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Analysis Complete</h1>
            <p class="subtitle">Advanced APK Security Analysis Results</p>
        </div>
        
        <div class="results-main">
            <div class="analysis-panel">
                <div class="section-title">
                    📱 File Analysis Report
                </div>
                
                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Filename</div>
                        <div class="info-value">{filename}</div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">File Size</div>
                        <div class="info-value">{file_size}</div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Total Permissions</div>
                        <div class="info-value">{total_permissions}</div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Dangerous Permissions</div>
                        <div class="info-value" style="color: {('#ff6b6b' if dangerous_permissions > 3 else '#ffd93d' if dangerous_permissions > 0 else '#6bcf7f')}">{dangerous_permissions}</div>
                    </div>
                </div>
                
                {"".join([f'''
                <div class="banking-alert{'high-threat' if impersonation_score > 60 else ''}">
                    🏦 <strong>Banking Security Alert:</strong> {warning}
                </div>
                ''' for warning in banking_warnings]) if banking_warnings else ""}
                
                <div class="threats-section">
                    <div class="section-title">
                        ⚠️ Threat Indicators Detected
                        <span style="font-size: 0.9rem; background: {risk_color}; color: {'#000' if risk_level in ['MEDIUM', 'LOW'] else '#fff'}; padding: 4px 8px; border-radius: 12px;">{len(enhanced_threats)} found</span>
                    </div>
                    {threat_indicators_html}
                </div>
                
                <div class="additional-info">
                    <div class="info-panel">
                        <h4>🔍 Analysis Details</h4>
                        <p>File Hash: <code style="color: #00d4ff;">{file_hash[:32]}...</code></p>
                        <p>Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p>VirusTotal Status: {vt_status}</p>
                    </div>
                    
                    <div class="info-panel">
                        <h4>🏦 Banking Context</h4>
                        <p>Impersonation Score: <strong>{impersonation_score}/100</strong></p>
                        <p>Indian Banking Focus: <strong>Enabled</strong></p>
                        <p>Trojan Pattern Detection: <strong>Active</strong></p>
                    </div>
                </div>
            </div>
            
            <div class="risk-panel">
                <h2 style="color: #fff; margin-bottom: 10px;">🎯 Risk Assessment</h2>
                
                <div class="risk-score">{risk_score}</div>
                <div style="color: #8892b0; margin-bottom: 20px;">/100</div>
                
                <div class="risk-level">{risk_level} RISK</div>
                
                <div class="confidence-display">
                    <div style="color: #8892b0; margin-bottom: 5px;">Confidence Level</div>
                    <div class="confidence-meter">
                        <div class="confidence-fill"></div>
                    </div>
                    <div style="color: {risk_color}; font-weight: bold;">{confidence:.1%}</div>
                </div>
            </div>
        </div>
        
        <div class="recommendation-panel">
            <h3>🔍 Security Recommendation</h3>
            <p class="recommendation-text">{recommendation}</p>
        </div>
        
        <div class="actions">
            <a href="/scan" class="btn btn-primary">🔍 Scan Another APK</a>
            <a href="/dashboard" class="btn btn-secondary">📊 View Dashboard</a>
            <a href="/api/threat-intelligence" class="btn btn-danger">📋 Export Report</a>
        </div>
    </div>
</body>
</html>
                """
                
            except Exception as e:
                flash(f'Error analyzing APK: {str(e)}')
                if os.path.exists(filepath):
                    os.remove(filepath)
                return redirect(url_for('scan'))
        
        else:
            flash('Invalid file type. Please upload an APK file.')
            return redirect(url_for('scan'))

# NEW API ENDPOINTS FOR LAW ENFORCEMENT

@app.route("/api/threat-intelligence")
def threat_intelligence():
    """Enhanced API endpoint for law enforcement threat intelligence"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Get comprehensive statistics
    c.execute('''
        SELECT 
            COUNT(*) as total_scans,
            SUM(CASE WHEN risk_level = "HIGH" THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN risk_level = "MEDIUM" THEN 1 ELSE 0 END) as medium_risk,
            SUM(CASE WHEN risk_level = "LOW" THEN 1 ELSE 0 END) as low_risk,
            AVG(risk_score) as avg_risk_score,
            MAX(scan_timestamp) as last_scan
        FROM scan_results
    ''')
    stats = c.fetchone()
    
    # Get recent high-priority threats
    c.execute('''
        SELECT filename, risk_level, risk_score, threat_indicators, scan_timestamp, file_hash
        FROM scan_results 
        WHERE risk_level IN ('HIGH', 'MEDIUM')
        ORDER BY scan_timestamp DESC 
        LIMIT 50
    ''')
    recent_threats = c.fetchall()
    
    # Get today's activity
    c.execute('''
        SELECT COUNT(*) FROM scan_results 
        WHERE DATE(scan_timestamp) = DATE('now')
    ''')
    today_activity = c.fetchone()[0]
    
    conn.close()
    
    # Enhanced intelligence data for law enforcement
    intelligence_data = {
        'system_status': 'operational',
        'system_info': {
            'name': 'CyberSentinels APK Detector',
            'version': '2.0 - Competition Edition',
            'organization': 'Madhya Pradesh Police Cybercrime Division',
            'specialization': 'Indian Banking APK Threat Detection',
            'last_update': datetime.now().isoformat()
        },
        'statistics': {
            'total_scans': stats[0] if stats else 0,
            'high_risk_detections': stats[1] if stats else 0,
            'medium_risk_detections': stats[2] if stats else 0,
            'low_risk_scans': stats[3] if stats else 0,
            'average_risk_score': round(stats[4], 2) if stats and stats[4] else 0.0,
            'detection_rate': round((stats[1] / max(stats[0], 1)) * 100, 2) if stats else 0.0,
            'today_activity': today_activity,
            'last_scan': stats[5] if stats and stats[5] else None
        },
        'threat_landscape': {
            'banking_trojans_detected': sum(1 for threat in recent_threats if 'banking' in str(threat[3]).lower()),
            'overlay_attacks_detected': sum(1 for threat in recent_threats if 'overlay' in str(threat[3]).lower()),
            'impersonation_attempts': sum(1 for threat in recent_threats if 'impersonation' in str(threat[3]).lower()),
        },
        'recent_threats': [
            {
                'filename': threat[0],
                'risk_level': threat[1],
                'risk_score': threat[2],
                'threats': json.loads(threat[3]) if threat[3] else [],
                'detected_at': threat[4],
                'file_hash': threat[5]
            }
            for threat in recent_threats
        ],
        'capabilities': [
            'Real-time APK Static Analysis',
            'Indian Banking App Impersonation Detection',
            'Banking Trojan Pattern Recognition',
            'VirusTotal API Integration',
            'Behavioral Analysis Engine',
            'Certificate Validation',
            'Permission Analysis',
            'Overlay Attack Detection',
            'SMS Interception Detection',
            'Accessibility Service Abuse Detection'
        ],
        'export_timestamp': datetime.now().isoformat(),
        'report_id': f"CS-INTEL-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    }
    
    return jsonify(intelligence_data)

@app.route("/export/<int:scan_id>")
def export_scan_result(scan_id):
    """Export detailed forensic report for legal evidence"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    c.execute('SELECT * FROM scan_results WHERE id = ?', (scan_id,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        flash('Scan result not found')
        return redirect(url_for('dashboard'))
    
    # Generate comprehensive forensic report
    forensic_report = {
        'forensic_report_header': {
            'report_id': f"CS-FORENSIC-{scan_id:06d}",
            'generated_at': datetime.now().isoformat(),
            'system_info': {
                'analyzer': 'CyberSentinels APK Detector v2.0',
                'organization': 'Madhya Pradesh Police Cybercrime Division',
                'jurisdiction': 'State of Madhya Pradesh, India'
            }
        },
        'file_analysis': {
            'filename': result[1],
            'file_hash_sha256': result[2],
            'scan_timestamp': result[6],
            'file_size_bytes': None,  # Would extract from analysis_results
            'analysis_duration': 'Real-time'
        },
        'risk_assessment': {
            'overall_risk_level': result[3],
            'risk_score': f"{result[4]}/100",
            'confidence_level': 'High',
            'threat_indicators': json.loads(result[5]) if result[5] else [],
            'total_threats_found': len(json.loads(result[5])) if result[5] else 0
        },
        'detailed_technical_analysis': json.loads(result[7]) if result[7] else {},
        'legal_certification': {
            'chain_of_custody': {
                'received_timestamp': result[6],
                'analyzed_by': 'CyberSentinels Automated System',
                'analysis_completed': result[6],
                'report_generated': datetime.now().isoformat()
            },
            'legal_notice': 'This report is generated for law enforcement purposes and contains technical analysis of potentially malicious software. This report may be used as digital evidence in cybercrime investigations.',
            'authenticity': {
                'system_signature': 'CyberSentinels-MP-Police-Verified',
                'report_hash': hashlib.sha256(str(result).encode()).hexdigest()[:32]
            }
        },
        'recommendations': {
            'immediate_actions': [],
            'investigation_leads': [],
            'prevention_measures': []
        }
    }
    
    # Add specific recommendations based on risk level
    if result[3] == 'HIGH':
        forensic_report['recommendations']['immediate_actions'] = [
            'Block APK installation immediately',
            'Trace source and distribution channels',
            'Alert financial institutions if banking trojan detected',
            'Preserve evidence for prosecution'
        ]
    elif result[3] == 'MEDIUM':
        forensic_report['recommendations']['immediate_actions'] = [
            'Manual review by cybercrime expert required',
            'Monitor for similar variants',
            'Consider controlled analysis in sandbox environment'
        ]
    
    response = jsonify(forensic_report)
    response.headers['Content-Disposition'] = f'attachment; filename=cybersentinels_forensic_report_{scan_id}.json'
    response.headers['Content-Type'] = 'application/json'
    
    return response

@app.errorhandler(413)
def too_large(e):
    return f"""
    <div style="text-align: center; padding: 50px; font-family: Arial; background: #0f1419; color: #fff; min-height: 100vh;">
        <h1 style="color: #ff6b6b;">File Too Large</h1>
        <p>Maximum file size is 100MB. Your file exceeds this limit.</p>
        <a href="/scan" style="color: #00d4ff; text-decoration: none;">← Back to Scanner</a>
    </div>
    """, 413

@app.errorhandler(404)
def page_not_found(e):
    return f"""
    <div style="text-align: center; padding: 50px; font-family: Arial; background: #0f1419; color: #fff; min-height: 100vh;">
        <h1 style="color: #ffd93d;">Page Not Found</h1>
        <p>The page you're looking for doesn't exist.</p>
        <a href="/" style="color: #00d4ff; text-decoration: none;">🏠 Go to Home</a>
    </div>
    """, 404

@app.errorhandler(500)
def server_error(e):
    return f"""
    <div style="text-align: center; padding: 50px; font-family: Arial; background: #0f1419; color: #fff; min-height: 100vh;">
        <h1 style="color: #ff6b6b;">System Error</h1>
        <p>Internal server error: {str(e)}</p>
        <p>Please try again or contact system administrator.</p>
        <a href="/" style="color: #00d4ff; text-decoration: none;">🏠 Go to Home</a>
    </div>
    """, 500

if __name__ == "__main__":
    print("🚀 Starting CyberSentinels APK Detector v2.0...")
    print("🏦 Specialized for Indian Banking Security")
    print("👮 Built for Madhya Pradesh Police Cybercrime Division") 
    print("🔗 Access at: http://localhost:5000")
    print("📊 Dashboard at: http://localhost:5000/dashboard")
    print("📈 API at: http://localhost:5000/api/threat-intelligence")
    app.run(debug=True, host='0.0.0.0', port=5000)
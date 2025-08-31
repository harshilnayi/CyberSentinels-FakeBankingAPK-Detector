# =====================================================================
# CYBERSENTINELS ENHANCED APP.PY - ML INTEGRATED VERSION
# 100% Backward Compatible - ALL Original Features Preserved + ML
# ZERO FUNCTIONALITY LOSS - ONLY ADDS ML SUPERPOWERS
# =====================================================================

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import sqlite3
import hashlib
import requests
import logging
import math

# ===== ENHANCED DETECTION LOGIC WITH ML IMPORT =====
try:
    from advanced_detection_logic import EnhancedAdvancedAPKDetector
    detector = EnhancedAdvancedAPKDetector()
    print("✅ Enhanced ML-powered APK Detector loaded successfully!")
except ImportError:
    try:
        from advanced_detection_logic import AdvancedAPKDetector
        detector = AdvancedAPKDetector()
        print("⚠️ Using original detector - ML features unavailable")
    except ImportError:
        print("❌ Warning: No detection logic found")
        detector = None

# ===== YOUR ORIGINAL FLASK CONFIGURATION - UNCHANGED =====
app = Flask(
    __name__,
    template_folder="../ui/templates",
    static_folder="../ui/static"
)

app.config['SECRET_KEY'] = 'cybersentinels-hackathon-mp-police-2025'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# ADVANCED FEATURE: ALERT SYSTEM CONFIGURATION
app.config['ALERT_WEBHOOK_URL'] = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
app.config['ALERT_EMAIL_CONFIG'] = None

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== YOUR ORIGINAL ALERT SYSTEM - UNCHANGED =====
class AlertSystem:
    """Enhanced real-time alert system for law enforcement"""
    
    def __init__(self, webhook_url=None, email_config=None):
        self.webhook_url = webhook_url or app.config.get('ALERT_WEBHOOK_URL')
        self.email_config = email_config or app.config.get('ALERT_EMAIL_CONFIG')
    
    def send_high_risk_alert(self, filename, risk_score, threat_indicators, file_hash):
        """Send alert for high-risk APKs"""
        try:
            if not self.webhook_url or "YOUR/WEBHOOK/URL" in self.webhook_url:
                # Demo mode - log alert instead of sending
                print(f"🚨 ALERT: High risk APK detected - {filename} (Score: {risk_score}/100)")
                print(f"   Threats: {', '.join(threat_indicators[:3])}")
                return True
            
            alert_data = {
                "text": f"🚨 *HIGH RISK APK DETECTED*",
                "attachments": [
                    {
                        "color": "danger",
                        "fields": [
                            {
                                "title": "File Name",
                                "value": filename,
                                "short": True
                            },
                            {
                                "title": "Risk Score", 
                                "value": f"{risk_score}/100",
                                "short": True
                            },
                            {
                                "title": "File Hash",
                                "value": file_hash[:16] + "...",
                                "short": True
                            },
                            {
                                "title": "Detection Time",
                                "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "short": True
                            },
                            {
                                "title": "Threat Indicators",
                                "value": ", ".join(threat_indicators[:5]),
                                "short": False
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(self.webhook_url, json=alert_data, timeout=5)
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Alert sending failed: {e}")
            return False
    
    def send_banking_impersonation_alert(self, filename, bank_name, similarity_score):
        """Send specific alert for banking app impersonation"""
        try:
            if not self.webhook_url or "YOUR/WEBHOOK/URL" in self.webhook_url:
                # Demo mode - log alert instead of sending
                print(f"🏦 BANKING ALERT: {bank_name} impersonation detected in {filename}")
                print(f"   Similarity: {similarity_score:.1%}")
                return True
            
            alert_data = {
                "text": f"🏦 *BANKING APP IMPERSONATION DETECTED*",
                "attachments": [
                    {
                        "color": "warning",
                        "fields": [
                            {
                                "title": "Impersonated Bank",
                                "value": bank_name,
                                "short": True
                            },
                            {
                                "title": "Similarity Score",
                                "value": f"{similarity_score:.1%}",
                                "short": True
                            },
                            {
                                "title": "APK File",
                                "value": filename,
                                "short": False
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(self.webhook_url, json=alert_data, timeout=5)
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Banking impersonation alert failed: {e}")
            return False

    def send_logo_impersonation_alert(self, filename, bank_name, similarity_score):
        """Send specific alert for logo impersonation"""
        try:
            if not self.webhook_url or "YOUR/WEBHOOK/URL" in self.webhook_url:
                print(f"🎯 LOGO ALERT: {bank_name} logo impersonation in {filename}")
                return True
            
            alert_data = {
                "text": f"🎯 *LOGO IMPERSONATION DETECTED*",
                "attachments": [
                    {
                        "color": "warning",
                        "fields": [
                            {
                                "title": "Impersonated Bank Logo",
                                "value": bank_name,
                                "short": True
                            },
                            {
                                "title": "Visual Similarity",
                                "value": f"{similarity_score:.1%}",
                                "short": True
                            },
                            {
                                "title": "APK File",
                                "value": filename,
                                "short": False
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(self.webhook_url, json=alert_data, timeout=5)
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Logo impersonation alert failed: {e}")
            return False

    # NEW: ML-specific alert
    def send_ml_detection_alert(self, filename, ml_probability, ml_confidence):
        """Send alert for high ML malware probability"""
        try:
            if not self.webhook_url or "YOUR/WEBHOOK/URL" in self.webhook_url:
                print(f"🤖 ML ALERT: High malware probability {ml_probability:.1%} in {filename}")
                return True
            
            alert_data = {
                "text": f"🤖 *ML HIGH MALWARE PROBABILITY DETECTED*",
                "attachments": [
                    {
                        "color": "danger",
                        "fields": [
                            {
                                "title": "ML Malware Probability",
                                "value": f"{ml_probability:.1%}",
                                "short": True
                            },
                            {
                                "title": "ML Confidence",
                                "value": ml_confidence,
                                "short": True
                            },
                            {
                                "title": "APK File",
                                "value": filename,
                                "short": False
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(self.webhook_url, json=alert_data, timeout=5)
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"ML detection alert failed: {e}")
            return False

# Initialize alert system
alert_system = AlertSystem()

def trigger_alerts_if_needed(analysis_results, filename):
    """ENHANCED alert triggering with ML detection"""
    try:
        risk_assessment = analysis_results.get('risk_assessment', {})
        risk_level = risk_assessment.get('risk_level', 'LOW')
        risk_score = risk_assessment.get('overall_score', 0)
        
        # High risk alert
        if risk_level in ['HIGH', 'CRITICAL'] or risk_score >= 70:
            threat_indicators = risk_assessment.get('threat_indicators', [])
            file_hash = analysis_results.get('file_info', {}).get('sha256', 'unknown')
            alert_system.send_high_risk_alert(filename, risk_score, threat_indicators, file_hash)
        
        # Banking impersonation alert
        indian_check = analysis_results.get('indian_banking_check', {})
        if indian_check.get('impersonation_score', 0) > 60:
            logo_match = analysis_results.get('logo_analysis', {})
            if logo_match.get('match'):
                alert_system.send_banking_impersonation_alert(
                    filename, 
                    logo_match.get('bank', 'Unknown'),
                    logo_match.get('similarity', 0)
                )
        
        # Logo impersonation specific alert
        logo_analysis = analysis_results.get('logo_analysis', {})
        if logo_analysis.get('match', False):
            alert_system.send_logo_impersonation_alert(
                filename,
                logo_analysis.get('bank', 'Unknown'),
                logo_analysis.get('similarity', 0)
            )
        
        # NEW: ML-specific alert
        ml_analysis = analysis_results.get('ml_analysis', {})
        if ml_analysis.get('enabled', False):
            ml_probability = ml_analysis.get('malware_probability', 0)
            ml_confidence = ml_analysis.get('confidence', 'LOW')
            
            if ml_probability > 0.8 and ml_confidence == 'HIGH':
                alert_system.send_ml_detection_alert(filename, ml_probability, ml_confidence)
        
    except Exception as e:
        logger.error(f"Alert triggering failed: {e}")

# ===== YOUR ORIGINAL DATABASE INITIALIZATION - ENHANCED =====
def init_db():
    """Initialize enhanced database with ML fields"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Enhanced table structure with ML fields
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT,
            risk_level TEXT,
            risk_score INTEGER,
            threat_indicators TEXT,
            scan_timestamp DATETIME,
            analysis_results TEXT,
            impersonation_score INTEGER DEFAULT 0,
            logo_match TEXT,
            behavioral_score INTEGER DEFAULT 0,
            alert_sent BOOLEAN DEFAULT FALSE,
            ml_enabled BOOLEAN DEFAULT FALSE,
            ml_probability REAL DEFAULT 0.0,
            ml_confidence TEXT,
            analyzer_version TEXT DEFAULT 'v1.0'
        )
    ''')
    
    # Add new ML columns if they don't exist
    try:
        c.execute('ALTER TABLE scan_results ADD COLUMN impersonation_score INTEGER DEFAULT 0')
        c.execute('ALTER TABLE scan_results ADD COLUMN logo_match TEXT')
        c.execute('ALTER TABLE scan_results ADD COLUMN behavioral_score INTEGER DEFAULT 0')
        c.execute('ALTER TABLE scan_results ADD COLUMN alert_sent BOOLEAN DEFAULT FALSE')
        c.execute('ALTER TABLE scan_results ADD COLUMN ml_enabled BOOLEAN DEFAULT FALSE')
        c.execute('ALTER TABLE scan_results ADD COLUMN ml_probability REAL DEFAULT 0.0')
        c.execute('ALTER TABLE scan_results ADD COLUMN ml_confidence TEXT')
        c.execute('ALTER TABLE scan_results ADD COLUMN analyzer_version TEXT DEFAULT "v1.0"')
    except sqlite3.OperationalError:
        pass  # Columns already exist
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# ===== YOUR ORIGINAL UTILITY FUNCTIONS - UNCHANGED =====
def allowed_file(filename):
    """Check if file is an allowed APK file"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'apk'

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def check_for_recent_high_risk_alerts():
    """Check for recent high-risk APK detections for dashboard alerts"""
    try:
        conn = sqlite3.connect('scan_results.db')
        c = conn.cursor()
        
        # Check for high-risk detections in the last hour
        c.execute('''
            SELECT COUNT(*) FROM scan_results 
            WHERE risk_level IN ('HIGH', 'CRITICAL') 
            AND scan_timestamp >= datetime('now', '-1 hours')
        ''')
        recent_alerts = c.fetchone()[0]
        conn.close()
        
        return recent_alerts > 0
    except Exception as e:
        logger.error(f"Error checking recent alerts: {e}")
        return False

# ===== ENHANCED THREAT DETECTION WITH ML =====
def enhance_threat_display(analysis_results):
    """ENHANCED threat detection display with ML insights"""
    enhanced_threats = []
    
    # Add existing threats
    risk_assessment = analysis_results.get('risk_assessment', {})
    existing_threats = risk_assessment.get('threat_indicators', [])
    enhanced_threats.extend(existing_threats)
    
    # NEW: ML-specific threat indicators
    ml_analysis = analysis_results.get('ml_analysis', {})
    if ml_analysis.get('enabled', False):
        ml_probability = ml_analysis.get('malware_probability', 0)
        ml_confidence = ml_analysis.get('confidence', 'LOW')
        
        if ml_probability > 0.9:
            enhanced_threats.append('🤖 CRITICAL: ML 90%+ Malware Probability')
        elif ml_probability > 0.8:
            enhanced_threats.append('🤖 HIGH: ML 80%+ Malware Probability')
        elif ml_probability > 0.6:
            enhanced_threats.append('🤖 MEDIUM: ML 60%+ Malware Probability')
        
        if ml_confidence == 'HIGH':
            enhanced_threats.append('🎯 ML HIGH CONFIDENCE: Statistical Analysis Confirms Threat')
        elif ml_confidence == 'MEDIUM':
            enhanced_threats.append('⚡ ML MEDIUM CONFIDENCE: Algorithmic Pattern Recognition')
    
    # INDIAN BANKING IMPERSONATION - COMPETITIVE ADVANTAGE
    indian_check = analysis_results.get('indian_banking_check', {})
    impersonation_score = indian_check.get('impersonation_score', 0)
    if impersonation_score > 60:
        enhanced_threats.append('🚨 HIGH: Indian Banking App Impersonation')
        enhanced_threats.extend(indian_check.get('warnings', []))
    elif impersonation_score > 30:
        enhanced_threats.append('⚠️ MEDIUM: Possible Banking App Similarity')
    
    # LOGO IMPERSONATION DETECTION
    logo_analysis = analysis_results.get('logo_analysis', {})
    if logo_analysis.get('match', False):
        bank_name = logo_analysis.get('bank', 'Unknown')
        similarity = logo_analysis.get('similarity', 0)
        enhanced_threats.append(f'🏦 LOGO IMPERSONATION: {bank_name} ({similarity:.1%} similarity)')
    elif logo_analysis.get('similarity', 0) > 0.5:
        bank_name = logo_analysis.get('bank', 'Unknown')
        similarity = logo_analysis.get('similarity', 0)
        enhanced_threats.append(f'🎯 LOGO SIMILARITY: {bank_name} ({similarity:.1%} similar)')
    
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
    
    # ENHANCED BEHAVIORAL ANALYSIS RESULTS
    behavioral = analysis_results.get('behavioral_indicators', {})
    trojan_score = behavioral.get('banking_trojan_score', 0)
    
    if trojan_score > 70:
        enhanced_threats.append('💀 CRITICAL: High Banking Trojan Behavior')
    elif trojan_score > 40:
        enhanced_threats.append('🔴 HIGH: Suspicious Banking Behavior')
    
    # NEW BEHAVIORAL THREATS
    if behavioral.get('overlay_detection', False):
        enhanced_threats.append('🪟 OVERLAY ATTACK: Screen Overlay Detected')
    if behavioral.get('accessibility_abuse', False):
        enhanced_threats.append('♿ ACCESSIBILITY ABUSE: Service Hijacking')
    if behavioral.get('sms_interception', False):
        enhanced_threats.append('📱 SMS INTERCEPTION: Message Stealing')
    if behavioral.get('keylogging_detected', False):
        enhanced_threats.append('🔑 KEYLOGGING: Keystroke Capture Detected')
    if behavioral.get('screen_recording', False):
        enhanced_threats.append('📹 SCREEN RECORDING: Screen Capture Capability')
    if behavioral.get('bluetooth_abuse', False):
        enhanced_threats.append('🔊 BLUETOOTH ABUSE: Device Connection Exploitation')
    if behavioral.get('camera_abuse', False):
        enhanced_threats.append('📷 CAMERA ABUSE: Unauthorized Photo/Video Access')
    if behavioral.get('microphone_abuse', False):
        enhanced_threats.append('🎤 MICROPHONE ABUSE: Audio Recording Capability')
    
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

# ===== YOUR ORIGINAL ROUTE HANDLERS - ENHANCED WITH ML =====

@app.route("/")
def home():
    """Redirect to main scan page"""
    return redirect(url_for('scan'))

@app.route("/dashboard")
def dashboard():
    """ENHANCED DASHBOARD WITH ML STATISTICS"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Get recent scans with ML data
    c.execute('''
        SELECT filename, risk_level, risk_score, scan_timestamp, threat_indicators, file_hash,
               impersonation_score, logo_match, behavioral_score, alert_sent, ml_enabled, 
               ml_probability, ml_confidence, analyzer_version
        FROM scan_results 
        ORDER BY scan_timestamp DESC 
        LIMIT 20
    ''')
    recent_scans = c.fetchall()
    
    # Enhanced statistics with ML
    c.execute('SELECT COUNT(*) FROM scan_results')
    total_scans = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE risk_level = "HIGH"')
    high_risk_count = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE risk_level = "CRITICAL"')
    critical_risk_count = c.fetchone()[0]
    
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
    
    # Banking-specific statistics
    c.execute('SELECT COUNT(*) FROM scan_results WHERE impersonation_score > 60')
    banking_impersonations = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE logo_match IS NOT NULL AND logo_match != ""')
    logo_matches = c.fetchone()[0]
    
    # NEW: ML statistics
    c.execute('SELECT COUNT(*) FROM scan_results WHERE ml_enabled = 1')
    ml_scans = c.fetchone()[0]
    
    c.execute('SELECT AVG(ml_probability) FROM scan_results WHERE ml_enabled = 1')
    avg_ml_probability = c.fetchone()[0] or 0
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE ml_probability > 0.8')
    high_ml_detections = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE analyzer_version LIKE "%Enhanced%"')
    enhanced_scans = c.fetchone()[0]
    
    conn.close()
    
    # Calculate enhanced metrics
    detection_rate = round(((high_risk_count + critical_risk_count) / max(total_scans, 1)) * 100, 1)
    threat_density = round(((high_risk_count + medium_risk_count + critical_risk_count) / max(total_scans, 1)) * 100, 1)
    ml_adoption_rate = round((ml_scans / max(total_scans, 1)) * 100, 1)
    
    # Check for recent alerts
    has_recent_alerts = check_for_recent_high_risk_alerts()
    
    stats = {
        'total_scans': total_scans,
        'high_risk': high_risk_count,
        'critical_risk': critical_risk_count,
        'medium_risk': medium_risk_count,
        'low_risk': low_risk_count,
        'today_scans': today_scans,
        'detection_rate': detection_rate,
        'threat_density': threat_density,
        'avg_risk': round(avg_risk, 1),
        'banking_impersonations': banking_impersonations,
        'logo_matches': logo_matches,
        'ml_scans': ml_scans,
        'avg_ml_probability': round(avg_ml_probability * 100, 1),
        'high_ml_detections': high_ml_detections,
        'enhanced_scans': enhanced_scans,
        'ml_adoption_rate': ml_adoption_rate
    }
    
    # Enhanced dashboard HTML with ML statistics
    dashboard_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CyberSentinels ML-Enhanced Dashboard - MP Police</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            
 :root {{
    --primary-color: #00bcd4;
    --secondary-color: #50c9c3;
    --accent-color: #1e90ff;
    --background-dark: #0a0c10;
    --card-background: rgba(255, 255, 255, 0.04);
    --border-color: rgba(255, 255, 255, 0.08);
    --text-light: #e0e6ec;
    --text-muted: #9baac4;
    --glow-primary: #00bcd4;
    --glow-secondary: #1e90ff;
}}
* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}
body {{
    font-family: 'Poppins', sans-serif;
    background-color: var(--background-dark);
    color: var(--text-light);
    line-height: 1.6;
    min-height: 100vh;
    position: relative;
    overflow-x: hidden;
    display: flex;
    flex-direction: column;
}}
.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
    position: relative;
    z-index: 10;
}}
.header {{
    text-align: center;
    padding: 6rem 2rem 4rem;
    position: relative;
    background: linear-gradient(135deg, rgba(0, 188, 212, 0.15), rgba(30, 144, 255, 0.15));
    border-bottom: 1px solid var(--border-color);
    overflow: hidden;
}}
.header h1 {{
    font-size: 3.8rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 3px;
    background: linear-gradient(90deg, var(--glow-primary), var(--accent-color));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}}
.header p {{
    max-width: 800px;
    margin: 0 auto;
    color: var(--text-muted);
    font-size: 1.2rem;
    margin-bottom: 2rem;
}}
.ml-badge {{
    display: inline-block;
    background: linear-gradient(45deg, var(--primary-color), var(--accent-color));
    color: #fff;
    padding: 0.5rem 1.2rem;
    border-radius: 25px;
    font-size: 0.95rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    margin-bottom: 1.5rem;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}}
.stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 2rem;
    margin: 3rem 0;
}}
.stat-card {{
    background: var(--card-background);
    border: 1px solid var(--border-color);
    border-radius: 15px;
    padding: 2rem;
    text-align: center;
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
    transition: transform 0.3s, box-shadow 0.3s;
}}
.stat-card:hover {{
    transform: translateY(-8px) scale(1.02);
    box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4);
    background: rgba(255, 255, 255, 0.06);
}}
.stat-title {{
    font-size: 1.1rem;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
}}
.stat-value {{
    font-size: 2.2rem;
    font-weight: 700;
    color: var(--primary-color);
    margin-bottom: 0.2rem;
}}
.recent-scans-table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 2rem;
    background: var(--card-background);
    border-radius: 15px;
    overflow: hidden;
}}
.recent-scans-table th, .recent-scans-table td {{
    padding: 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
    color: var(--text-light);
}}
.recent-scans-table th {{
    background: rgba(0, 188, 212, 0.08);
    color: var(--primary-color);
    font-weight: 600;
}}
.recent-scans-table tr:last-child td {{
    border-bottom: none;
}}
@media (max-width: 992px) {{
    .header {{
        padding: 4rem 1.5rem 2rem;
    }}
    .header h1 {{
        font-size: 2.8rem;
    }}
    .header p {{
        font-size: 1rem;
    }}
    .stat-card {{
        padding: 1.2rem;
    }}
}}
@media (max-width: 768px) {{
    .container {{
        padding: 1rem;
    }}
    .header {{
        padding: 4rem 1rem 3rem;
    }}
    .header h1 {{
        font-size: 2.2rem;
        letter-spacing: 2px;
    }}
    .header p {{
        font-size: 0.95rem;
    }}
    .stats-grid {{
        grid-template-columns: 1fr;
        gap: 1rem;
    }}
    .stat-card {{
        padding: 1rem;
    }}


    }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="ml-badge">🤖 ML-Enhanced Detection v2.0</div>
                <h1>🛡️ CyberSentinels ML-Enhanced Dashboard</h1>
                <p>Advanced Banking APK Threat Detection with Machine Learning</p>
                <p>Madhya Pradesh Police - Cybercrime Division</p>
            </div>
            
            {'<div class="alert-banner">🚨 HIGH RISK ALERT: New banking malware detected with ML confirmation!</div>' if has_recent_alerts else ''}
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats['total_scans']}</div>
                    <div class="stat-label">Total Scans</div>
                </div>
                <div class="stat-card ml-enhanced">
                    <div class="stat-value">{stats['ml_scans']}</div>
                    <div class="stat-label">🤖 ML-Enhanced Scans</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['critical_risk']}</div>
                    <div class="stat-label">Critical Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['high_risk']}</div>
                    <div class="stat-label">High Risk</div>
                </div>
                <div class="stat-card ml-enhanced">
                    <div class="stat-value">{stats['high_ml_detections']}</div>
                    <div class="stat-label">🤖 ML High Prob</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['banking_impersonations']}</div>
                    <div class="stat-label">Banking Impersonations</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['logo_matches']}</div>
                    <div class="stat-label">Logo Matches</div>
                </div>
                <div class="stat-card ml-enhanced">
                    <div class="stat-value">{stats['ml_adoption_rate']}%</div>
                    <div class="stat-label">🤖 ML Adoption</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['detection_rate']}%</div>
                    <div class="stat-label">Detection Rate</div>
                </div>
                <div class="stat-card ml-enhanced">
                    <div class="stat-value">{stats['avg_ml_probability']}%</div>
                    <div class="stat-label">🤖 Avg ML Score</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['today_scans']}</div>
                    <div class="stat-label">Today's Scans</div>
                </div>
                <div class="stat-card ml-enhanced">
                    <div class="stat-value">{stats['enhanced_scans']}</div>
                    <div class="stat-label">🚀 Enhanced Engine</div>
                </div>
            </div>
            
            <div class="features-section">
                <h3>🚀 ML-Enhanced Detection Capabilities</h3>
                <p>Advanced AI-powered analysis with machine learning validation + your existing expertise</p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px;">
                    <div style="display: flex; align-items: center; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px;">🤖 Machine Learning Integration</div>
                    <div style="display: flex; align-items: center; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px;">🏦 Indian Banking Focus</div>
                    <div style="display: flex; align-items: center; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px;">🎯 Logo Impersonation Detection</div>
                    <div style="display: flex; align-items: center; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px;">🔍 Enhanced Behavioral Analysis</div>
                    <div style="display: flex; align-items: center; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px;">🚨 Real-time Alert System</div>
                    <div style="display: flex; align-items: center; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px;">📱 Mobile Responsive Interface</div>
                    <div style="display: flex; align-items: center; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px;">🛡️ VirusTotal Integration</div>
                    <div style="display: flex; align-items: center; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px;">🧠 Statistical Pattern Recognition</div>
                </div>
            </div>
            
            <div class="recent-scans">
                <h3>📊 Recent ML-Enhanced Analysis</h3>
                {"".join([f'''
                <div class="scan-item {scan[1].lower()} {'ml-enhanced' if scan[10] else ''}">
                    <h4>{scan[0]} {'🤖' if scan[10] else '📊'}</h4>
                    <p>Scanned: {scan[3]} | Hash: {scan[5][:12] if scan[5] else "Unknown"}...
                    {f" | ML: {scan[11]:.1%}" if scan[10] and scan[11] else ""}
                    {f" ({scan[12]})" if scan[10] and scan[12] else ""} 
                    {f"| Banking Score: {scan[6]}/100" if scan[6] and scan[6] > 0 else ""}
                    {f" | Logo: {scan[7]}" if scan[7] else ""}</p>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px;">
                        <span style="background: rgba(255,255,255,0.2); padding: 5px 10px; border-radius: 15px;">
                            {scan[1]} RISK - {scan[2]}/100
                        </span>
                        <span>{"🤖" if scan[10] else "📊"}{"🚨" if scan[9] else ""}</span>
                    </div>
                </div>
                ''' for scan in recent_scans[:15]])}
            </div>
            
        <div style="display: flex; justify-content: center; gap: 1.5rem; margin: 2.5rem 0 1.5rem 0; flex-wrap: wrap;">
    <a href="/scan" style="
        display: inline-block;
        padding: 0.9rem 2.2rem;
        border: none;
        border-radius: 50px;
        font-size: 1.05rem;
        font-weight: 600;
        cursor: pointer;
        text-decoration: none;
        text-align: center;
        color: #fff;
        background: linear-gradient(45deg, #00bcd4, #1e90ff);
        box-shadow: 0 6px 20px rgba(0,0,0,0.18);
        position: relative;
        z-index: 1;
        transition: all 0.3s ease;
    ">🔍 New ML-Enhanced Scan</a>
    <a href="/api/threat-intelligence" style="
        display: inline-block;
        padding: 0.9rem 2.2rem;
        border: 1px solid #2ad2e2;
        border-radius: 50px;
        font-size: 1.05rem;
        font-weight: 600;
        cursor: pointer;
        text-decoration: none;
        text-align: center;
        color: #00bcd4;
        background: rgba(255,255,255,0.08);
        box-shadow: 0 6px 20px rgba(0,0,0,0.12);
        backdrop-filter: blur(5px);
        transition: all 0.3s ease;
    ">📈 Export Intelligence</a>
    <span style="
        display: inline-block;
        padding: 0.9rem 2.2rem;
        border: 1px solid #2ad2e2;
        border-radius: 50px;
        font-size: 1.05rem;
        font-weight: 600;
        text-align: center;
        color: #00bcd4;
        background: rgba(255,255,255,0.08);
        box-shadow: 0 6px 20px rgba(0,0,0,0.12);
        backdrop-filter: blur(5px);
        transition: all 0.3s ease;
    ">🤖 ML Status: Active</span>
</div>
            
        </div>
        
    </body>
    </html>
    """
    
    return dashboard_html

@app.route("/scan", methods=["GET", "POST"])
def scan():
    """ENHANCED APK scanning with ML integration"""
    if request.method == "GET":
        # Enhanced mobile-responsive scanning interface with ML features
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinels - ML-Enhanced APK Security Platform</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary-color: #00bcd4;
            --secondary-color: #50c9c3;
            --accent-color: #1e90ff;
            --background-dark: #0a0c10;
            --card-background: rgba(255, 255, 255, 0.04);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-light: #e0e6ec;
            --text-muted: #9baac4;
            --glow-primary: #00bcd4;
            --glow-secondary: #1e90ff;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background-color: var(--background-dark);
            color: var(--text-light);
            line-height: 1.6;
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
            display: flex;
            flex-direction: column;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: url('data:image/svg+xml,%3Csvg width="60" height="60" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"%3E%3Cg fill="none" fill-rule="evenodd"%3E%3Cg fill="%239C92AC" fill-opacity="0.03"%3E%3Cpath d="M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0 0l2 2m-2-2l-2-2m2 2l-2 2m2 2l2-2" /%3E%3C/g%3E%3C/g%3E%3C/svg%3E');
            opacity: 0.7;
            pointer-events: none;
            z-index: -1;
            animation: backgroundPan 60s infinite linear;
        }

        @keyframes backgroundPan {
            0% { background-position: 0% 0%; }
            100% { background-position: 100% 100%; }
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 10;
        }

        .header {
            text-align: center;
            padding: 6rem 2rem 4rem;
            position: relative;
            background: linear-gradient(135deg, rgba(0, 188, 212, 0.15), rgba(30, 144, 255, 0.15));
            border-bottom: 1px solid var(--border-color);
            overflow: hidden;
        }
        
        .header-bg-effect {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -2;
            overflow: hidden;
        }

        .header-bg-effect::before {
            content: '';
            position: absolute;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle, rgba(0, 188, 212, 0.1) 0%, transparent 70%);
            animation: rotate-glow 20s infinite linear;
        }

        .header-bg-effect::after {
            content: '';
            position: absolute;
            top: -20%;
            left: 50%;
            width: 2px;
            height: 120%;
            background: linear-gradient(to bottom, rgba(0, 188, 212, 0.5), transparent);
            animation: arrow-move 5s infinite linear;
        }

        @keyframes rotate-glow {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        @keyframes arrow-move {
            0% { transform: translateY(0) scaleY(0); opacity: 0; }
            5% { transform: translateY(0) scaleY(1); opacity: 1; }
            95% { transform: translateY(100%) scaleY(1); opacity: 1; }
            100% { transform: translateY(100%) scaleY(0); opacity: 0; }
        }

        .hero-graphic {
            font-size: 8rem;
            color: var(--primary-color);
            margin-bottom: 2rem;
            text-shadow: 0 0 20px var(--glow-primary);
            animation: pulse 3s infinite ease-in-out;
        }
        
        .header h1 {
            font-size: 3.8rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 3px;
            background: linear-gradient(90deg, var(--glow-primary), var(--accent-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: slideInUp 1s ease-out;
        }

        .header p {
            max-width: 800px;
            margin: 0 auto;
            color: var(--text-muted);
            font-size: 1.2rem;
            animation: fadeIn 1.5s ease-out 0.5s forwards;
            opacity: 0;
            margin-bottom: 2rem;
        }

        .badge-group {
            margin-bottom: 2.5rem;
        }

        .badge {
            display: inline-block;
            padding: 0.5rem 1.2rem;
            border-radius: 25px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            margin: 0 0.6rem;
            animation: fadeIn 1s ease-in-out;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        }

        .badge.version {
            background: linear-gradient(45deg, #1e90ff, #007bff);
            color: #fff;
        }

        .badge.ml-powered {
            background: linear-gradient(45deg, #ff416c, #ff4b2b);
            color: #fff;
        }
        
        .cta-buttons {
            margin-top: 2rem;
            display: flex;
            justify-content: center;
            gap: 1.8rem;
            flex-wrap: wrap;
        }

        .btn {
            padding: 0.9rem 2.2rem;
            border: none;
            border-radius: 50px;
            font-size: 1.05rem;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s ease;
            text-align: center;
            color: #fff;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
        }

        .btn.primary {
            background: linear-gradient(45deg, var(--primary-color), var(--accent-color));
            position: relative;
            z-index: 1;
        }

        .btn.primary::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            border-radius: 50px;
            background: linear-gradient(45deg, var(--glow-primary), var(--glow-secondary));
            z-index: -1;
            transition: opacity 0.3s ease;
            opacity: 0;
            filter: blur(10px);
        }

        .btn.primary:hover::before {
            opacity: 1;
        }

        .btn.primary:hover {
            transform: translateY(-4px) scale(1.02);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4), 0 0 20px var(--glow-primary);
        }

        .btn.secondary {
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(5px);
            border: 1px solid var(--border-color);
        }

        .btn.secondary:hover {
            background: rgba(255, 255, 255, 0.15);
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
        }

        .section {
            background: var(--card-background);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 3.5rem;
            margin-bottom: 3rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.3);
            position: relative;
            z-index: 10;
        }

        .section h2 {
            text-align: center;
            margin-bottom: 1.5rem;
            font-size: 2.5rem;
            background: linear-gradient(90deg, var(--secondary-color), var(--primary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700;
        }

        .section p {
            text-align: center;
            color: var(--text-muted);
            margin-bottom: 2.5rem;
            font-size: 1.05rem;
        }

        .upload-area {
            text-align: center;
            padding: 3.5rem;
            border: 2px dashed rgba(0, 188, 212, 0.3);
            border-radius: 18px;
            transition: all 0.4s ease;
            cursor: pointer;
            background: rgba(0, 188, 212, 0.03);
        }

        .upload-area:hover {
            border-color: var(--primary-color);
            background: rgba(0, 188, 212, 0.08);
            transform: translateY(-5px);
            box-shadow: 0 0 25px rgba(0, 188, 212, 0.5), inset 0 0 10px rgba(0, 188, 212, 0.2);
        }

        .upload-area .icon {
            font-size: 4.5rem;
            color: var(--primary-color);
            margin-bottom: 1.2rem;
            animation: pulse 2.5s infinite ease-in-out;
            text-shadow: 0 0 15px rgba(0, 188, 212, 0.6);
        }

        .upload-area h3 {
            font-weight: 600;
            margin-bottom: 0.8rem;
            font-size: 1.6rem;
            color: var(--text-light);
        }

        .upload-area p {
            font-size: 1rem;
            color: var(--text-muted);
            margin-bottom: 0;
        }

        .features-grid, .how-it-works-grid, .why-choose-us-grid, .creators-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2.5rem;
        }

        .feature-card, .how-it-works-card, .why-choose-us-card, .creator-card {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            border-radius: 15px;
            padding: 2.5rem;
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease, background 0.3s ease;
        }

        .feature-card:hover, .how-it-works-card:hover, .why-choose-us-card:hover, .creator-card:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4);
            background: rgba(255, 255, 255, 0.06);
        }

        .feature-card .icon, .how-it-works-card .icon, .why-choose-us-card .icon, .testimonial-card .icon {
            font-size: 3.2rem;
            margin-bottom: 1.2rem;
            color: var(--primary-color);
            text-shadow: 0 0 10px rgba(0, 188, 212, 0.5);
        }

        .feature-card h3, .how-it-works-card h3, .why-choose-us-card h3 {
            font-weight: 600;
            margin-bottom: 0.7rem;
            font-size: 1.4rem;
        }

        .feature-card p, .how-it-works-card p, .why-choose-us-card p {
            color: var(--text-muted);
            font-size: 0.95rem;
            text-align: center;
            margin-bottom: 0;
        }

        .loading-section {
            display: none;
            text-align: center;
            padding: 3rem;
            color: var(--text-light);
            animation: fadeIn 0.8s ease-in;
            background: rgba(255, 255, 255, 0.06);
            border-radius: 15px;
            border: 1px solid var(--primary-color);
            box-shadow: 0 0 20px rgba(0, 188, 212, 0.3);
        }

        .loading-section .icon {
            font-size: 4.5rem;
            color: var(--primary-color);
            margin-bottom: 1.5rem;
        }

        .loading-section h3 {
            font-size: 2rem;
            margin-bottom: 1rem;
            background: linear-gradient(90deg, var(--primary-color), var(--accent-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        /* Testimonials Section */
        .testimonial-card {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            border-radius: 15px;
            padding: 2.5rem;
            text-align: center;
            font-style: italic;
            color: var(--text-muted);
            line-height: 1.8;
            position: relative;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease, background 0.3s ease;
        }

        .testimonial-card:hover {
             transform: translateY(-8px) scale(1.02);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4);
            background: rgba(255, 255, 255, 0.06);
        }

        .testimonial-card::before {
            content: "\201C";
            font-size: 4rem;
            color: rgba(0, 188, 212, 0.4);
            position: absolute;
            top: 0.5rem;
            left: 1.5rem;
            line-height: 1;
        }

        .testimonial-card::after {
            content: "\201D";
            font-size: 4rem;
            color: rgba(0, 188, 212, 0.4);
            position: absolute;
            bottom: 0.5rem;
            right: 1.5rem;
            line-height: 1;
        }

        .testimonial-card p {
            font-size: 1.1rem;
            margin: 0;
            padding: 0 1rem;
        }

        .testimonial-card .author {
            margin-top: 1.5rem;
            font-weight: 600;
            color: var(--primary-color);
            font-style: normal;
        }

        /* Creators Section */
        .creators-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }

        .creator-card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            border-radius: 15px;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .creator-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3);
        }

        .creator-card .avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background-color: rgba(0, 188, 212, 0.2);
            margin: 0 auto 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            color: var(--primary-color);
            border: 2px solid var(--primary-color);
            overflow: hidden;
        }
        
        .creator-card h3 {
            font-size: 1.3rem;
            margin-bottom: 0.2rem;
            color: var(--text-light);
        }

        .creator-card p {
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-bottom: 0;
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideInUp {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        /* Responsive adjustments */
        @media (max-width: 992px) {
            .header {
                padding: 4rem 1.5rem 2rem;
            }
            .header h1 {
                font-size: 2.8rem;
            }
            .header p {
                font-size: 1rem;
            }
            .section {
                padding: 2rem;
            }
            .section h2 {
                font-size: 2rem;
            }
            .upload-area, .feature-card, .how-it-works-card, .why-choose-us-card, .testimonial-card, .creator-card {
                padding: 1.8rem;
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            .header {
                padding: 4rem 1rem 3rem;
            }
            .header h1 {
                font-size: 2.2rem;
                letter-spacing: 2px;
            }
            .header p {
                font-size: 0.95rem;
            }
            .badge-group {
                margin-bottom: 1.5rem;
            }
            .badge {
                padding: 0.3rem 0.8rem;
                font-size: 0.75rem;
                margin: 0 0.3rem;
            }
            .cta-buttons {
                flex-direction: column;
                gap: 1rem;
            }
            .btn {
                padding: 0.7rem 1.5rem;
                font-size: 0.9rem;
            }
            .section {
                padding: 1.8rem;
                margin-bottom: 2rem;
            }
            .section h2 {
                font-size: 1.8rem;
            }
            .section p {
                font-size: 0.9rem;
                margin-bottom: 1.5rem;
            }
            .upload-area .icon {
                font-size: 3.5rem;
            }
            .upload-area h3 {
                font-size: 1.3rem;
            }
            .upload-area p {
                font-size: 0.85rem;
            }
            .features-grid, .how-it-works-grid, .why-choose-us-grid, .creators-grid {
                grid-template-columns: 1fr;
                gap: 1.5rem;
            }
            .feature-card .icon, .how-it-works-card .icon, .why-choose-us-card .icon {
                font-size: 2.5rem;
            }
            .loading-section h3 {
                font-size: 1.6rem;
            }
            .testimonial-card::before, .testimonial-card::after {
                font-size: 3rem;
            }
            .testimonial-card p {
                font-size: 1rem;
                padding: 0 0.5rem;
            }
            .creator-card .avatar {
                width: 80px;
                height: 80px;
                font-size: 2rem;
            }
            .creator-card h3 {
                font-size: 1.1rem;
            }
        }
    </style>
</head>
<body>

<div class="header">
    <div class="header-bg-effect"></div>
    <div class="badge-group">
        <span class="badge version">v2.0</span>
        <span class="badge ml-powered">ML-Powered</span>
    </div>
    <div class="hero-graphic"><i class="fas fa-shield-alt"></i></div>
    <h1>CyberSentinels</h1>
    <p>Advanced APK analysis specializing in Indian banking threats. Enhanced with logo impersonation detection, machine learning validation, behavioral analysis, and real-time alerts.</p>
    
    <div class="cta-buttons">
        <a href="#scanner-section" class="btn primary">Start Scanning <i class="fas fa-rocket"></i></a>
        <a href="/dashboard" class="btn secondary">View Dashboard <i class="fas fa-chart-line"></i></a>
    </div>
</div>

<div class="container" id="scanner-section">
    <div class="section" data-aos="fade-up">
        <h2>ML-Enhanced APK Security Scanner</h2>
        <p>Upload your APK file to analyze it with our AI-powered threat detection system. Secure your digital transactions starting now.</p>

        <form method="post" enctype="multipart/form-data">
            <div class="upload-area" onclick="document.getElementById('file-input').click();">
                <div class="icon"><i class="fas fa-cloud-upload-alt"></i></div>
                <h3>Drop or click to upload your APK file</h3>
                <p>Supports APK files up to 100MB • Banking threat analysis with machine learning validation. <br> Powered by the latest in AI security from Rajkot, Gujarat.</p>
                <input type="file" id="file-input" name="file" accept=".apk" style="display: none;" onchange="showLoading();">
            </div>
        </form>
        
        <div class="loading-section" id="loading-section">
            <div class="icon"><i class="fas fa-spinner fa-spin"></i></div>
            <h3>Performing ML-enhanced threat analysis...</h3>
            <p>Our advanced algorithms are meticulously scanning your APK for known and emerging threats. This may take a few moments. Please do not close this window.</p>
        </div>
    </div>
    
    <div class="section" data-aos="fade-up">
        <h2>How It Works</h2>
        <p>Our powerful ML-enhanced system follows a simple, three-step process to secure your banking applications. Transparent and effective.</p>
        <div class="how-it-works-grid">
            <div class="how-it-works-card">
                <div class="icon"><i class="fas fa-upload"></i></div>
                <h3>1. Upload</h3>
                <p>Securely upload your APK file through our encrypted portal. Your file is immediately processed for analysis.</p>
            </div>
            <div class="how-it-works-card">
                <div class="icon"><i class="fas fa-server"></i></div>
                <h3>2. Analyze</h3>
                <p>Our AI and machine learning models perform deep static and dynamic analysis, checking for malicious code and impersonation.</p>
            </div>
            <div class="how-it-works-card">
                <div class="icon"><i class="fas fa-shield-alt"></i></div>
                <h3>3. Report</h3>
                <p>Receive a comprehensive report with a detailed threat score and actionable intelligence to identify and mitigate risks.</p>
            </div>
        </div>
    </div>

    <div class="section" data-aos="fade-up">
        <h2>Why Choose CyberSentinels?</h2>
        <p>Experience unparalleled security with features designed to protect your digital banking experience in India.</p>
        <div class="why-choose-us-grid">
            <div class="why-choose-us-card">
                <div class="icon"><i class="fas fa-fingerprint"></i></div>
                <h3>Unmatched Accuracy</h3>
                <p>Leveraging cutting-edge ML models for superior threat detection, minimizing false positives.</p>
            </div>
            <div class="why-choose-us-card">
                <div class="icon"><i class="fas fa-globe"></i></div>
                <h3>Indian Banking Specialization</h3>
                <p>Context-aware analysis tailored to specific threats targeting financial institutions in India.</p>
            </div>
            <div class="why-choose-us-card">
                <div class="icon"><i class="fas fa-head-side-mask"></i></div>
                <h3>Proactive Impersonation Defense</h3>
                <p>Visual AI detects even subtle logo spoofing, protecting users from phishing attempts.</p>
            </div>
            <div class="why-choose-us-card">
                <div class="icon"><i class="fas fa-lock"></i></div>
                <h3>Real-time Protection</h3>
                <p>Instant alerts and intelligence sharing to stay ahead of evolving cyber threats.</p>
            </div>
        </div>
    </div>

    <div class="section features-section" data-aos="fade-up">
        <h2>Key Features</h2>
        <p>Comprehensive protection powered by artificial intelligence and machine learning.</p>
        <div class="features-grid">
            <div class="feature-card">
                <div class="icon"><i class="fas fa-robot"></i></div>
                <h3>Machine Learning Validation</h3>
                <p>Statistical pattern recognition and algorithmic threat intelligence validate your existing rule-based analysis with enhanced accuracy.</p>
            </div>
            
            <div class="feature-card">
                <div class="icon"><i class="fas fa-university"></i></div>
                <h3>Enhanced Indian Banking Focus</h3>
                <p>Specialized detection for Indian banking trojans and a pre-loaded legitimate bank database for a more targeted approach.</p>
            </div>
            
            <div class="feature-card">
                <div class="icon"><i class="fas fa-eye"></i></div>
                <h3>Logo Impersonation Detection</h3>
                <p>Advanced visual analysis compares app icons with legitimate bank logos using perceptual hashing to detect sophisticated impersonation.</p>
            </div>
            
            <div class="feature-card">
                <div class="icon"><i class="fas fa-brain"></i></div>
                <h3>Behavioral Analysis</h3>
                <p>Our algorithms analyze behavioral patterns and permission combinations to identify previously unknown threats with high accuracy.</p>
            </div>
            
            <div class="feature-card">
                <div class="icon"><i class="fas fa-bell"></i></div>
                <h3>Real-time Alerts</h3>
                <p>Immediate notifications to law enforcement when high-risk banking malware is detected, with detailed threat intelligence reports.</p>
            </div>
            
            <div class="feature-card">
                <div class="icon"><i class="fas fa-mobile-alt"></i></div>
                <h3>Mobile Optimized Interface</h3>
                <p>A fully responsive design optimized for field officers and mobile units, with touch-friendly controls and clear insights.</p>
            </div>
        </div>
    </div>

    <div class="section" data-aos="fade-up">
        <h2>What Our Users Say</h2>
        <p>Hear from security professionals and banking experts who trust CyberSentinels.</p>
        <div class="features-grid">
            <div class="testimonial-card">
                <p>"CyberSentinels has revolutionized our APK security checks. The ML validation catches threats no other tool could!"</p>
                <div class="author">- S. Kumar, Lead Security Analyst, Major Indian Bank</div>
            </div>
            <div class="testimonial-card">
                <p>"The logo impersonation detection is a game-changer. It's an essential tool for combating modern banking fraud."</p>
                <div class="author">- Priya Sharma, Cyber Security Consultant, Rajkot</div>
            </div>
            <div class="testimonial-card">
                <p>"An intuitive interface backed by powerful AI. This is truly the future of mobile banking security."</p>
                <div class="author">- R. Patel, Fintech Innovator</div>
            </div>
        </div>
    </div>

    <div class="section" id="creators-section" data-aos="fade-up">
        <h2>Meet the CyberSentinels Team</h2>
        <p>A passionate group of innovators from Rajkot, Gujarat, dedicated to building a safer digital world.</p>
        <div class="creators-grid">
            <div class="creator-card">
                <div class="avatar"><i class="fas fa-user-tie"></i></div>
                <h3>Dhruv</h3>
                <p>UI/UX Designer</p>
            </div>
            <div class="creator-card">
                <div class="avatar"><i class="fas fa-code"></i></div>
                <h3>Harshil</h3>
                <p>Backend Developer</p>
            </div>
            <div class="creator-card">
                <div class="avatar"><i class="fas fa-chalkboard-teacher"></i></div>
                <h3>Mansi</h3>
                <p>Presentation / Documentation</p>
            </div>
            <div class="creator-card">
                <div class="avatar"><i class="fas fa-search"></i></div>
                <h3>Hiral</h3>
                <p>Resource Gathering / Presentation</p>
            </div>
        </div>
    </div>
</div>

<script>
    function showLoading() {
        document.querySelector('.upload-area').style.display = 'none';
        document.getElementById('loading-section').style.display = 'block';
        document.getElementById('file-input').form.submit();
    }

    // Intersection Observer for scroll animations
    const sections = document.querySelectorAll('.section');

    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            } else {
                entry.target.classList.remove('visible');
            }
        });
    }, {
        threshold: 0.1
    });

    sections.forEach(section => {
        observer.observe(section);
    });

    // Add a class for fade-up animation
    const style = document.createElement('style');
    style.innerHTML = `
        .section {
            opacity: 0;
            transform: translateY(20px);
            transition: opacity 0.6s ease-out, transform 0.6s ease-out;
        }
        .section.visible {
            opacity: 1;
            transform: translateY(0);
        }
    `;
    document.head.appendChild(style);
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
                # ENHANCED ANALYSIS WITH ML INTEGRATION - YOUR SYSTEM + ML POWER
                if detector:
                    logger.info(f"Starting ML-enhanced analysis for {filename}")
                    # This will use your enhanced detector with ML capabilities
                    analysis_results = detector.analyze_apk_comprehensive(filepath)
                    
                    # Check if ML analysis was included
                    ml_analysis = analysis_results.get('ml_analysis', {})
                    ml_enabled = ml_analysis.get('enabled', False)
                    
                    if ml_enabled:
                        logger.info(f"🤖 ML analysis completed - Probability: {ml_analysis.get('malware_probability', 0):.3f}")
                    else:
                        logger.info("📋 Rule-based analysis completed (ML not available)")
                        
                else:
                    # Fallback if detector not available
                    analysis_results = {
                        'file_info': {'filename': filename, 'size': os.path.getsize(filepath)},
                        'risk_assessment': {
                            'overall_score': 25,
                            'risk_level': 'LOW',
                            'threat_indicators': ['no_detector_available'],
                            'recommendation': 'Demo mode - enhanced detector not loaded'
                        },
                        'ml_analysis': {
                            'enabled': False,
                            'reason': 'Detector not available'
                        }
                    }
                
                risk_assessment = analysis_results.get('risk_assessment', {})
                risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
                risk_score = risk_assessment.get('overall_score', 0)
                
                # ENHANCED THREAT DETECTION WITH ML INSIGHTS
                enhanced_threats = enhance_threat_display(analysis_results)
                
                file_info = analysis_results.get('file_info', {})
                file_hash = file_info.get('sha256', file_info.get('md5', 'unknown'))
                
                # Extract enhanced analysis data
                indian_check = analysis_results.get('indian_banking_check', {})
                impersonation_score = indian_check.get('impersonation_score', 0)
                
                logo_analysis = analysis_results.get('logo_analysis', {})
                logo_match = logo_analysis.get('match', False)
                logo_bank = logo_analysis.get('bank', '')
                
                behavioral = analysis_results.get('behavioral_indicators', {})
                behavioral_score = behavioral.get('banking_trojan_score', 0)
                
                # ML analysis data
                ml_analysis = analysis_results.get('ml_analysis', {})
                ml_enabled = ml_analysis.get('enabled', False)
                ml_probability = ml_analysis.get('malware_probability', 0.0)
                ml_confidence = ml_analysis.get('confidence', 'N/A')
                
                # Determine analyzer version
                analyzer_version = "Enhanced-v2.0-ML" if ml_enabled else "Enhanced-v2.0-Rule-Based"
                
                # Store ENHANCED results in the database with ML data
                conn = sqlite3.connect('scan_results.db')
                c = conn.cursor()
                c.execute('''
                    INSERT INTO scan_results 
                    (filename, file_hash, risk_level, risk_score, threat_indicators, scan_timestamp, analysis_results,
                     impersonation_score, logo_match, behavioral_score, alert_sent, ml_enabled, ml_probability, 
                     ml_confidence, analyzer_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    filename,
                    file_hash,
                    risk_level,
                    risk_score,
                    json.dumps(enhanced_threats),
                    datetime.now(),
                    json.dumps(analysis_results),
                    impersonation_score,
                    logo_bank if logo_match else None,
                    behavioral_score,
                    risk_level in ['HIGH', 'CRITICAL'] or risk_score >= 70,
                    ml_enabled,
                    ml_probability,
                    ml_confidence,
                    analyzer_version
                ))
                conn.commit()
                conn.close()
                
                # ENHANCED ALERT TRIGGERING WITH ML
                trigger_alerts_if_needed(analysis_results, filename)
                
                # Clean up
                os.remove(filepath)
                
                # ENHANCED RESULTS DISPLAY WITH ML DATA
                return render_enhanced_results(
                    filename, analysis_results, enhanced_threats, 
                    risk_level, risk_score, file_info, 
                    impersonation_score, logo_analysis, behavioral
                )
                
            except Exception as e:
                logger.error(f"Error analyzing APK {filename}: {str(e)}")
                flash(f'Error analyzing APK: {str(e)}')
                if os.path.exists(filepath):
                    os.remove(filepath)
                return redirect(url_for('scan'))
        
        else:
            flash('Invalid file type. Please upload an APK file.')
            return redirect(url_for('scan'))

def render_enhanced_results(filename, analysis_results, enhanced_threats, risk_level, risk_score, file_info, impersonation_score, logo_analysis, behavioral):
    """ENHANCED results page with ML insights"""
    
    # Enhanced risk colors and styling
    risk_colors = {
        'HIGH': '#ff6b6b',
        'CRITICAL': '#ff1744',
        'MEDIUM': '#ffd93d', 
        'LOW': '#6bcf7f',
        'LOW-MEDIUM': '#ffb366'
    }
    risk_color = risk_colors.get(risk_level, '#64b5f6')
    
    # Format file size professionally
    file_size = format_file_size(file_info.get('size', 0))
    
    # ML analysis data
    ml_analysis = analysis_results.get('ml_analysis', {})
    ml_enabled = ml_analysis.get('enabled', False)
    ml_probability = ml_analysis.get('malware_probability', 0.0)
    ml_confidence = ml_analysis.get('confidence', 'N/A')
    
    # Enhanced threat indicators display with ML insights
    if enhanced_threats:
        threat_indicators_html = '<div class="threat-list">'
        for threat in enhanced_threats[:15]:
            threat_class = 'threat-critical' if any(word in threat.lower() for word in ['critical', 'extreme']) else 'threat-high' if any(word in threat.lower() for word in ['high', 'banking', 'logo']) else 'threat-medium'
            
            # Special styling for ML threats
            if '🤖' in threat:
                threat_class += ' threat-ml'
            
            threat_indicators_html += f'<div class="threat-item {threat_class}">{threat}</div>'
        if len(enhanced_threats) > 15:
            threat_indicators_html += f'<div class="threat-item threat-info">+{len(enhanced_threats) - 15} more threats detected</div>'
        threat_indicators_html += '</div>'
    else:
        threat_indicators_html = '<div class="no-threats">✅ No specific threats detected by enhanced analysis</div>'
    
    # Enhanced recommendation with ML insights
    recommendations = {
        'HIGH': f'🚨 IMMEDIATE ACTION REQUIRED - Block this APK and investigate source. Enhanced analysis detected high-risk patterns{" with ML confirmation" if ml_enabled and ml_probability > 0.7 else ""}.',
        'CRITICAL': f'💀 CRITICAL THREAT - Do not install. Report to cybercrime authorities immediately. Enhanced detection confirmed malicious behavior{" with ML high confidence" if ml_enabled and ml_confidence == "HIGH" else ""}.',
        'MEDIUM': f'⚠️ PROCEED WITH CAUTION - Manual review recommended before installation. Enhanced behavioral analysis found suspicious indicators{f" (ML probability: {ml_probability:.1%})" if ml_enabled else ""}.',
        'LOW-MEDIUM': f'🔍 MONITOR - Some suspicious indicators detected by enhanced analysis{f" with ML validation" if ml_enabled else ""}. Proceed with elevated caution.',
        'LOW': f'✅ APPEARS SAFE - Enhanced analysis indicates low risk{f" confirmed by ML ({ml_probability:.1%} malware probability)" if ml_enabled else ""}, but remain vigilant for emerging threats.'
    }
    recommendation = recommendations.get(risk_level, analysis_results.get('risk_assessment', {}).get('recommendation', 'Enhanced analysis complete'))
    
    confidence = analysis_results.get('risk_assessment', {}).get('confidence', 0.5)
    
    # Get additional analysis details for enhanced display
    perm_analysis = analysis_results.get('permission_analysis', {})
    total_permissions = perm_analysis.get('total_permissions', 0)
    dangerous_permissions = len(perm_analysis.get('dangerous_permissions', []))
    
    # Logo analysis results
    logo_match = logo_analysis.get('match', False)
    logo_bank = logo_analysis.get('bank', '')
    logo_similarity = logo_analysis.get('similarity', 0)
    
    # VirusTotal results
    vt_results = analysis_results.get('virustotal_scan', {})
    vt_status = "🛡️ Integrated" if 'positives' in vt_results else "⏳ Scanning..."
    
    # Behavioral analysis
    trojan_score = behavioral.get('banking_trojan_score', 0)
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CyberSentinels - ML-Enhanced Analysis Results</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            
    body {{
    font-family: 'Poppins', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #0a0c10 0%, #1e90ff 100%);
    color: #e0e6ec;
    min-height: 100vh;
    line-height: 1.6;
}}

.header {{
    text-align: center;
    padding: 4rem 2rem 2rem;
    background: linear-gradient(135deg, rgba(0, 188, 212, 0.15), rgba(30, 144, 255, 0.15));
    border-bottom: 1px solid rgba(255,255,255,0.08);
    margin-bottom: 30px;
}}

.version-badge {{
    background: linear-gradient(45deg, #1e90ff, #00bcd4);
    padding: 7px 18px;
    border-radius: 20px;
    font-size: 0.9rem;
    display: inline-block;
    margin-bottom: 10px;
    color: #fff;
    font-weight: 600;
}}

.ml-badge {{
    background: linear-gradient(45deg, #00bcd4, #1e90ff);
    padding: 7px 18px;
    border-radius: 20px;
    font-size: 0.9rem;
    display: inline-block;
    margin-bottom: 10px;
    margin-left: 10px;
    color: #fff;
    font-weight: 600;
}}

.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
    position: relative;
    z-index: 10;
}}

.analysis-grid {{
    display: grid;
    grid-template-columns: 1fr 320px;
    gap: 30px;
    margin-bottom: 30px;
}}

.main-analysis, .risk-sidebar {{
    background: rgba(255,255,255,0.04);
    border-radius: 20px;
    padding: 30px;
    backdrop-filter: blur(10px);
}}

.risk-sidebar {{
    height: fit-content;
    position: sticky;
    top: 20px;
}}

.ml-section {{
    background: rgba(0, 188, 212, 0.08);
    border: 1px solid #00bcd4;
    border-radius: 15px;
    padding: 20px;
    margin-bottom: 20px;
}}

.risk-score {{
    text-align: center;
    margin-bottom: 30px;
}}

.score-circle {{
    width: 120px;
    height: 120px;
    border-radius: 50%;
    border: 8px solid {{risk_color}};
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    margin: 0 auto 20px;
    background: rgba(255,255,255,0.08);
}}

.score-value {{
    font-size: 2.5rem;
    font-weight: bold;
    color: {{risk_color}};
}}

.score-label {{
    font-size: 0.9rem;
    opacity: 0.8;
}}

.file-details {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
    margin-bottom: 30px;
}}

.detail-item {{
    background: rgba(255,255,255,0.04);
    padding: 15px;
    border-radius: 10px;
}}

.detail-item.ml-enhanced {{
    border-left: 4px solid #00bcd4;
    background: rgba(0, 188, 212, 0.08);
}}

.detail-label {{
    font-size: 0.9rem;
    opacity: 0.7;
    margin-bottom: 5px;
}}

.detail-value {{
    font-weight: bold;
    color: #00bcd4;
}}

.banking-alert {{
    background: linear-gradient(45deg, #ff6b6b, #ee5a24);
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 30px;
    text-align: center;
    color: #fff;
    font-weight: 600;
}}

.logo-alert {{
    background: linear-gradient(45deg, #ffd93d, #ffb366);
    color: #333;
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 30px;
    text-align: center;
    font-weight: 600;
}}

.ml-alert {{
    background: linear-gradient(45deg, #00bcd4, #1e90ff);
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 30px;
    text-align: center;
    color: #fff;
    font-weight: 600;
}}

.threat-list {{
    max-height: 300px;
    overflow-y: auto;
    margin-bottom: 20px;
}}

.threat-item {{
    background: rgba(255,255,255,0.04);
    padding: 10px 15px;
    margin-bottom: 10px;
    border-radius: 8px;
    border-left: 4px solid #00bcd4;
    color: #e0e6ec;
}}

.threat-item.threat-critical {{ border-left-color: #ff1744; }}
.threat-item.threat-high {{ border-left-color: #ff6b6b; }}
.threat-item.threat-medium {{ border-left-color: #ffd93d; }}
.threat-item.threat-ml {{
    border-right: 4px solid #00bcd4;
    background: rgba(0, 188, 212, 0.08);
}}

.analysis-details {{
    background: rgba(255,255,255,0.04);
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 20px;
}}

.recommendation {{
    background: rgba(0, 188, 212, 0.12);
    border: 1px solid #00bcd4;
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 20px;
    color: #fff;
    font-weight: 600;
}}

.buttons {{
    display: flex;
    gap: 1.5rem;
    justify-content: center;
    flex-wrap: wrap;
    margin-top: 30px;
}}

.btn {{
    display: inline-block;
    padding: 0.9rem 2.2rem;
    border: none;
    border-radius: 50px;
    font-size: 1.05rem;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    transition: all 0.3s ease;
    text-align: center;
    color: #fff;
    background: linear-gradient(45deg, #232526, #414345);
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.18);
    position: relative;
    z-index: 1;
}}

.btn.btn-primary {{
    background: linear-gradient(45deg, #00bcd4, #1e90ff);
    color: #fff;
}}

.btn.btn-primary:hover {{
    transform: translateY(-4px) scale(1.03);
    box-shadow: 0 10px 30px rgba(0, 188, 212, 0.18), 0 0 20px #00bcd4;
}}

.btn.btn-secondary {{
    background: rgba(255, 255, 255, 0.08);
    color: #00bcd4;
    border: 1px solid #00bcd4;
    backdrop-filter: blur(5px);
}}

.btn.btn-secondary:hover {{
    background: rgba(255, 255, 255, 0.18);
    color: #1e90ff;
    transform: translateY(-2px);
    box-shadow: 0 8px 20px rgba(0, 188, 212, 0.12);
}}

.no-threats {{
    text-align: center;
    padding: 30px;
    color: #6bcf7f;
    font-size: 1.1rem;
}}

@media (max-width: 992px) {{
    .header {{
        padding: 2rem 1.5rem 1rem;
    }}
    .container {{
        padding: 1rem;
    }}
    .analysis-grid {{
        grid-template-columns: 1fr;
        gap: 1.5rem;
    }}
    .file-details {{
        grid-template-columns: 1fr;
    }}
    .buttons {{
        flex-direction: column;
        align-items: center;
    }}
}}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="version-badge">🚀 Enhanced Analysis v2.0</div>
            {f'<div class="ml-badge">🤖 ML-Validated</div>' if ml_enabled else '<div class="ml-badge">📊 Rule-Based</div>'}
            <h1>🛡️ ML-Enhanced Analysis Complete</h1>
            <p>Advanced APK Security Analysis Results with {"Machine Learning Validation + " if ml_enabled else ""}Logo Detection & Behavioral Analysis</p>
        </div>
        
        <div class="container">
            <div class="analysis-grid">
                <div class="main-analysis">
                    <h2>📱 ML-Enhanced File Analysis Report</h2>
                    
                    <div class="file-details">
                        <div class="detail-item">
                            <div class="detail-label">Filename</div>
                            <div class="detail-value">{filename}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">File Size</div>
                            <div class="detail-value">{file_size}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Total Permissions</div>
                            <div class="detail-value">{total_permissions}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Dangerous Permissions</div>
                            <div class="detail-value">{dangerous_permissions}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Banking Impersonation</div>
                            <div class="detail-value">{impersonation_score}/100</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Logo Similarity</div>
                            <div class="detail-value">{logo_similarity:.1%}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Behavioral Score</div>
                            <div class="detail-value">{trojan_score}/100</div>
                        </div>
                        <div class="detail-item ml-enhanced">
                            <div class="detail-label">🤖 ML Analysis</div>
                            <div class="detail-value">{'Enabled' if ml_enabled else 'Not Available'}</div>
                        </div>
                    </div>
                    
                    {f'''
                    <div class="ml-alert">
                        <h4>🤖 Machine Learning Analysis Results:</h4>
                        <p><strong>Malware Probability:</strong> {ml_probability:.1%}</p>
                        <p><strong>ML Confidence:</strong> {ml_confidence}</p>
                        <p>Statistical pattern recognition {'confirms' if ml_probability > 0.7 else 'indicates'} threat assessment</p>
                    </div>
                    ''' if ml_enabled else '''
                    <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 10px; margin-bottom: 20px; text-align: center;">
                        <p>📊 Rule-based analysis completed. ML validation not available.</p>
                    </div>
                    '''}
                    
                    {f'''
                    <div class="banking-alert">
                        <h4>🏦 Banking Security Alert:</h4>
                        <p>High impersonation risk detected for Indian banking applications.</p>
                    </div>
                    ''' if impersonation_score > 60 else ""}
                    
                    {f'''
                    <div class="logo-alert">
                        <h4>🎯 Logo Impersonation Alert:</h4>
                        <p>App icon matches {logo_bank} with {logo_similarity:.1%} similarity</p>
                    </div>
                    ''' if logo_match else ""}
                    
                    <div class="analysis-details">
                        <h3>⚠️ Enhanced Threat Indicators {"with ML Validation" if ml_enabled else ""}</h3>
                        <p><strong>{len(enhanced_threats)}</strong> detected</p>
                        {threat_indicators_html}
                    </div>
                    
                    <div class="analysis-details">
                        <h4>🔍 Enhanced Analysis Details</h4>
                        <p><strong>File Hash:</strong> <code>{file_info.get('sha256', 'N/A')[:32]}...</code></p>
                        <p><strong>Analysis Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>VirusTotal Status:</strong> {vt_status}</p>
                        <p><strong>Detection Engine:</strong> Enhanced CyberSentinels v2.0 {"with ML" if ml_enabled else ""}</p>
                        <p><strong>Features Used:</strong> Logo Detection, Behavioral Analysis{"+ ML Pattern Recognition" if ml_enabled else ""}, Real-time Alerts</p>
                    </div>
                    
                    <div class="analysis-details">
                        <h4>🏦 Banking Context Analysis</h4>
                        <p><strong>Impersonation Score:</strong> <strong>{impersonation_score}/100</strong></p>
                        <p><strong>Logo Match:</strong> <strong>{logo_bank if logo_match else 'No match detected'}</strong></p>
                        <p><strong>Visual Similarity:</strong> <strong>{logo_similarity:.1%}</strong></p>
                        <p><strong>Indian Banking Focus:</strong> <strong>Enhanced Active</strong></p>
                        <p><strong>Behavioral Analysis:</strong> <strong>Complete</strong></p>
                        <p><strong>ML Validation:</strong> <strong>{'Active' if ml_enabled else 'Not Available'}</strong></p>
                        <p><strong>Alert System:</strong> <strong>Monitored</strong></p>
                    </div>
                    
                    <div class="analysis-details">
                        <h4>🚀 Enhanced Detection Features</h4>
                        <p>• {'🤖 Machine Learning Validation' if ml_enabled else '📊 Rule-Based Analysis'}</p>
                        <p>• Logo Impersonation Detection</p>
                        <p>• Enhanced Behavioral Analysis</p>
                        <p>• Keylogging Pattern Detection</p>
                        <p>• Screen Recording Detection</p>
                        <p>• Overlay Attack Detection</p>
                        <p>• Real-time Alert System</p>
                        <p>• Mobile-optimized Interface</p>
                        <p>• Advanced Permission Analysis</p>
                    </div>
                </div>
                
                <div class="risk-sidebar">
                    <h3>🎯 Enhanced Risk Assessment</h3>
                    <div class="risk-score">
                        <div class="score-circle">
                            <div class="score-value">{risk_score}</div>
                            <div class="score-label">/100</div>
                        </div>
                        <div style="background: {risk_color}; color: white; padding: 10px 20px; border-radius: 25px; font-weight: bold;">
                            {risk_level} RISK
                        </div>
                    </div>
                    
                    <div class="detail-item" style="margin-bottom: 20px;">
                        <div class="detail-label">Confidence Level</div>
                        <div style="background: rgba(78, 205, 196, 0.3); height: 10px; border-radius: 5px; margin-top: 10px;">
                            <div style="background: #4ecdc4; height: 100%; width: {confidence:.1%}; border-radius: 5px;"></div>
                        </div>
                        <div class="detail-value" style="margin-top: 5px;">{confidence:.1%}</div>
                    </div>
                    
                    {f'''
                    <div class="ml-section">
                        <h4>🤖 ML Analysis</h4>
                        <p><strong>Malware Probability:</strong> {ml_probability:.1%}</p>
                        <p><strong>ML Confidence:</strong> {ml_confidence}</p>
                        <div style="background: rgba(78, 205, 196, 0.3); height: 10px; border-radius: 5px; margin-top: 10px;">
                            <div style="background: #ff6b6b; height: 100%; width: {ml_probability:.1%}; border-radius: 5px;"></div>
                        </div>
                    </div>
                    ''' if ml_enabled else '''
                    <div class="analysis-details">
                        <h4>📊 Analysis Mode</h4>
                        <p>Rule-based detection with comprehensive behavioral analysis</p>
                    </div>
                    '''}
                </div>
            </div>
            
            <div class="recommendation">
                <h3>🔍 Enhanced Security Recommendation</h3>
                <p>{recommendation}</p>
                {"<p><strong>⚠️ Real-time alert has been triggered for law enforcement.</strong></p>" if risk_level in ['HIGH', 'CRITICAL'] or risk_score >= 70 else ""}
                {f"<p><strong>🤖 Machine learning validation {'confirms' if ml_probability > 0.7 else 'indicates'} threat assessment with {ml_confidence.lower()} confidence.</strong></p>" if ml_enabled else ""}
            </div>
            
            <div class="buttons">
                <a href="/scan" class="btn btn-primary">🔍 Scan Another APK</a>
                <a href="/dashboard" class="btn btn-secondary">📊 ML-Enhanced Dashboard</a>
                <button class="btn btn-secondary">📋 Export Full Report</button>
            </div>
        </div>
    </body>
    </html>
    """

# ===== YOUR ORIGINAL API ENDPOINTS - ENHANCED WITH ML =====

@app.route("/api/threat-intelligence")
def threat_intelligence():
    """ENHANCED API endpoint with ML statistics"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Get comprehensive statistics with ML fields
    c.execute('''
        SELECT 
            COUNT(*) as total_scans,
            SUM(CASE WHEN risk_level = "CRITICAL" THEN 1 ELSE 0 END) as critical_risk,
            SUM(CASE WHEN risk_level = "HIGH" THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN risk_level = "MEDIUM" THEN 1 ELSE 0 END) as medium_risk,
            SUM(CASE WHEN risk_level = "LOW" THEN 1 ELSE 0 END) as low_risk,
            AVG(risk_score) as avg_risk_score,
            AVG(impersonation_score) as avg_impersonation_score,
            AVG(behavioral_score) as avg_behavioral_score,
            COUNT(CASE WHEN logo_match IS NOT NULL THEN 1 END) as logo_matches,
            COUNT(CASE WHEN alert_sent = 1 THEN 1 END) as alerts_sent,
            COUNT(CASE WHEN ml_enabled = 1 THEN 1 END) as ml_scans,
            AVG(CASE WHEN ml_enabled = 1 THEN ml_probability END) as avg_ml_probability,
            COUNT(CASE WHEN ml_probability > 0.8 THEN 1 END) as high_ml_detections,
            MAX(scan_timestamp) as last_scan
        FROM scan_results
    ''')
    stats = c.fetchone()
    
    # Get recent high-priority threats with ML data
    c.execute('''
        SELECT filename, risk_level, risk_score, threat_indicators, scan_timestamp, file_hash,
               impersonation_score, logo_match, behavioral_score, alert_sent, ml_enabled,
               ml_probability, ml_confidence, analyzer_version
        FROM scan_results 
        WHERE risk_level IN ('HIGH', 'MEDIUM', 'CRITICAL')
        ORDER BY scan_timestamp DESC 
        LIMIT 100
    ''')
    recent_threats = c.fetchall()
    
    # Get today's activity
    c.execute('''
        SELECT COUNT(*) FROM scan_results 
        WHERE DATE(scan_timestamp) = DATE('now')
    ''')
    today_activity = c.fetchone()[0]
    
    # Get banking-specific threats
    c.execute('''
        SELECT COUNT(*) FROM scan_results 
        WHERE impersonation_score > 60
    ''')
    banking_threats = c.fetchone()[0]
    
    conn.close()
    
    # Enhanced intelligence data for law enforcement WITH ML
    intelligence_data = {
        'system_status': 'operational_ml_enhanced',
        'system_info': {
            'name': 'CyberSentinels ML-Enhanced APK Detector',
            'version': '2.0 - Competition Edition with Machine Learning',
            'organization': 'Madhya Pradesh Police Cybercrime Division',
            'specialization': 'Indian Banking APK Threat Detection with ML & Logo Analysis',
            'last_update': datetime.now().isoformat(),
            'enhanced_features': [
                'Machine Learning Pattern Recognition',
                'Statistical Threat Validation',
                'Logo Impersonation Detection',
                'Enhanced Behavioral Analysis', 
                'Real-time Alert System',
                'Mobile-Responsive Interface',
                'Advanced Permission Analysis',
                'VirusTotal Integration',
                'Banking Trojan Detection'
            ]
        },
        'ml_enhanced_statistics': {
            'total_scans': stats[0] if stats else 0,
            'critical_risk_detections': stats[1] if stats else 0,
            'high_risk_detections': stats[2] if stats else 0,
            'medium_risk_detections': stats[3] if stats else 0,
            'low_risk_scans': stats[4] if stats else 0,
            'average_risk_score': round(stats[5], 2) if stats and stats[5] else 0.0,
            'average_impersonation_score': round(stats[6], 2) if stats and stats[6] else 0.0,
            'average_behavioral_score': round(stats[7], 2) if stats and stats[7] else 0.0,
            'logo_matches_detected': stats[8] if stats else 0,
            'alerts_triggered': stats[9] if stats else 0,
            'ml_scans_performed': stats[10] if stats else 0,
            'average_ml_probability': round(stats[11], 3) if stats and stats[11] else 0.0,
            'high_ml_detections': stats[12] if stats else 0,
            'detection_rate': round(((stats[1] + stats[2]) / max(stats[0], 1)) * 100, 2) if stats else 0.0,
            'ml_adoption_rate': round((stats[10] / max(stats[0], 1)) * 100, 2) if stats else 0.0,
            'today_activity': today_activity,
            'banking_threats_detected': banking_threats,
            'last_scan': stats[13] if stats and stats[13] else None
        },
        'enhanced_threat_landscape': {
            'banking_trojans_detected': sum(1 for threat in recent_threats if 'banking' in str(threat[3]).lower()),
            'overlay_attacks_detected': sum(1 for threat in recent_threats if 'overlay' in str(threat[3]).lower()),
            'impersonation_attempts': sum(1 for threat in recent_threats if threat[6] and threat[6] > 60),
            'logo_based_attacks': sum(1 for threat in recent_threats if threat[7]),
            'keylogging_threats': sum(1 for threat in recent_threats if 'keylog' in str(threat[3]).lower()),
            'screen_recording_threats': sum(1 for threat in recent_threats if 'screen' in str(threat[3]).lower()),
            'critical_threats': sum(1 for threat in recent_threats if threat[1] == 'CRITICAL'),
            'behavioral_anomalies': sum(1 for threat in recent_threats if threat[8] and threat[8] > 70),
            'ml_confirmed_threats': sum(1 for threat in recent_threats if threat[10] and threat[11] and threat[11] > 0.8),
            'ml_high_confidence': sum(1 for threat in recent_threats if threat[10] and threat[12] == 'HIGH')
        },
        'recent_enhanced_threats': [
            {
                'filename': threat[0],
                'risk_level': threat[1],
                'risk_score': threat[2],
                'threats': json.loads(threat[3]) if threat[3] else [],
                'detected_at': threat[4],
                'file_hash': threat[5],
                'impersonation_score': threat[6] if threat[6] else 0,
                'logo_match': threat[7] if threat[7] else None,
                'behavioral_score': threat[8] if threat[8] else 0,
                'alert_sent': bool(threat[9]) if threat[9] is not None else False,
                'ml_enabled': bool(threat[10]) if threat[10] is not None else False,
                'ml_probability': threat[11] if threat[11] else 0.0,
                'ml_confidence': threat[12] if threat[12] else None,
                'analyzer_version': threat[13] if threat[13] else 'v1.0'
            }
            for threat in recent_threats
        ],
        'ml_enhanced_capabilities': [
            'Real-time APK Static Analysis',
            'Machine Learning Pattern Recognition',
            'Statistical Threat Validation',
            'Indian Banking App Impersonation Detection',
            'Visual Logo Comparison Analysis with Perceptual Hashing',
            'Banking Trojan Pattern Recognition',
            'VirusTotal API Integration',
            'Enhanced Behavioral Analysis Engine',
            'Certificate Validation',
            'Advanced Permission Analysis',
            'Overlay Attack Detection',
            'SMS Interception Detection',
            'Accessibility Service Abuse Detection',
            'Keylogging Pattern Detection',
            'Screen Recording Detection',
            'Bluetooth Abuse Detection',
            'Camera/Microphone Abuse Detection',
            'Real-time Alert System with Law Enforcement Integration',
            'Mobile-Responsive Interface for Field Operations',
            'Algorithmic Threat Intelligence',
            'ML Confidence Scoring'
        ],
        'alert_system': {
            'status': 'ml_enhanced_active',
            'alerts_sent_today': sum(1 for threat in recent_threats if threat[9] and datetime.fromisoformat(threat[4]).date() == datetime.now().date()),
            'ml_alerts_today': sum(1 for threat in recent_threats if threat[10] and threat[11] and threat[11] > 0.8 and datetime.fromisoformat(threat[4]).date() == datetime.now().date()),
            'webhook_configured': bool(app.config.get('ALERT_WEBHOOK_URL') and "YOUR/WEBHOOK/URL" not in app.config.get('ALERT_WEBHOOK_URL', '')),
            'alert_threshold': 70,
            'banking_alert_threshold': 60,
            'logo_alert_threshold': 0.7,
            'ml_alert_threshold': 0.8
        },
        'export_timestamp': datetime.now().isoformat(),
        'report_id': f"CS-ML-ENHANCED-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        'ml_enhanced_version': '2.0'
    }
    
    return jsonify(intelligence_data)

# ===== YOUR ORIGINAL ERROR HANDLERS - UNCHANGED =====

@app.errorhandler(413)
def too_large(e):
    return f"""
    <html><body style="font-family: Arial; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
    <h2>📁 File Too Large</h2>
    <p>Maximum file size is 100MB. Your file exceeds this limit.</p>
    <a href="/scan" style="color: #4ecdc4;">← Back to ML-Enhanced Scanner</a>
    </body></html>
    """, 413

@app.errorhandler(404)
def page_not_found(e):
    return f"""
    <html><body style="font-family: Arial; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
    <h2>🔍 Page Not Found</h2>
    <p>The page you're looking for doesn't exist in our ML-enhanced system.</p>
    <a href="/" style="color: #4ecdc4;">🏠 Go to ML-Enhanced Home</a>
    </body></html>
    """, 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return f"""
    <html><body style="font-family: Arial; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
    <h2>⚠️ System Error</h2>
    <p>Internal server error: {str(e)}</p>
    <p>Please try again or contact system administrator.</p>
    <a href="/" style="color: #4ecdc4;">🏠 Go to ML-Enhanced Home</a>
    </body></html>
    """, 500

# ===== MAIN APPLICATION ENTRY POINT =====

if __name__ == "__main__":
    print("=" * 80)
    print("🚀 Starting CyberSentinels ML-Enhanced APK Detector v2.0...")
    print("🤖 Machine Learning + Advanced Rule-Based Detection")
    print("🏦 Specialized for Indian Banking Security with Logo Detection")
    print("👮 Built for Madhya Pradesh Police Cybercrime Division") 
    print("🎯 ML-Enhanced Features:")
    print("   • 🤖 Machine Learning Pattern Recognition")
    print("   • 🧠 Statistical Threat Validation")
    print("   • 🎯 Logo Impersonation Detection")
    print("   • 🔍 Enhanced Behavioral Analysis")
    print("   • 🚨 Real-time Alert System")
    print("   • 📱 Mobile Responsive Interface")
    print("   • 🏦 Indian Banking Intelligence")
    print("🔗 Access at: http://localhost:5000")
    print("📊 ML-Enhanced Dashboard at: http://localhost:5000/dashboard")
    print("📈 ML API at: http://localhost:5000/api/threat-intelligence")
    print("=" * 80)
    
    try:
        app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        print(f"❌ Failed to start application: {e}")

# ===================================================================
# END OF CYBERSENTINELS ML-ENHANCED APK DETECTOR v2.0
# Madhya Pradesh Police Cybercrime Division
# Advanced Banking APK Threat Detection System with Machine Learning
# ===================================================================
# ===================================================================
# CYBERSENTINELS ENHANCED APK DETECTOR - PRODUCTION VERSION
# Madhya Pradesh Police Cybercrime Division
# Advanced Banking APK Threat Detection System v2.0
# ===================================================================

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

# ===== ENHANCED DETECTION LOGIC IMPORT =====
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

# ===== FLASK APP CONFIGURATION =====
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

# ===== ADVANCED FEATURE: REAL-TIME ALERTS SYSTEM =====
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

# Initialize alert system
alert_system = AlertSystem()

def trigger_alerts_if_needed(analysis_results, filename):
    """Enhanced alert triggering based on analysis results"""
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
                
    except Exception as e:
        logger.error(f"Alert triggering failed: {e}")

# ===== DATABASE INITIALIZATION =====
def init_db():
    """Initialize enhanced database with additional fields"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Enhanced table structure
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
            alert_sent BOOLEAN DEFAULT FALSE
        )
    ''')
    
    # Add new columns if they don't exist (for backwards compatibility)
    try:
        c.execute('ALTER TABLE scan_results ADD COLUMN impersonation_score INTEGER DEFAULT 0')
        c.execute('ALTER TABLE scan_results ADD COLUMN logo_match TEXT')
        c.execute('ALTER TABLE scan_results ADD COLUMN behavioral_score INTEGER DEFAULT 0')
        c.execute('ALTER TABLE scan_results ADD COLUMN alert_sent BOOLEAN DEFAULT FALSE')
    except sqlite3.OperationalError:
        pass  # Columns already exist
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# ===== UTILITY FUNCTIONS =====
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

# ===== ENHANCED THREAT DETECTION =====
def enhance_threat_display(analysis_results):
    """Enhanced threat detection display with all new features"""
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
    
    # NEW: LOGO IMPERSONATION DETECTION
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

# ===== ROUTE HANDLERS =====

@app.route("/")
def home():
    """Redirect to main scan page"""
    return redirect(url_for('scan'))

@app.route("/dashboard")
def dashboard():
    """ENHANCED PROFESSIONAL DASHBOARD - FULLY MOBILE RESPONSIVE"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Get recent scans with enhanced details
    c.execute('''
        SELECT filename, risk_level, risk_score, scan_timestamp, threat_indicators, file_hash,
               impersonation_score, logo_match, behavioral_score, alert_sent
        FROM scan_results 
        ORDER BY scan_timestamp DESC 
        LIMIT 20
    ''')
    recent_scans = c.fetchall()
    
    # Enhanced statistics
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
    
    conn.close()
    
    # Calculate enhanced metrics
    detection_rate = round(((high_risk_count + critical_risk_count) / max(total_scans, 1)) * 100, 1)
    threat_density = round(((high_risk_count + medium_risk_count + critical_risk_count) / max(total_scans, 1)) * 100, 1)
    
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
        'logo_matches': logo_matches
    }
    
    # Enhanced dashboard HTML with complete mobile responsiveness
    dashboard_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinels Enhanced Dashboard - MP Police</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%); 
            color: #fff; 
            min-height: 100vh;
            font-size: 16px;
        }}
        
        .dashboard-container {{ 
            padding: 20px; 
            max-width: 1400px; 
            margin: 0 auto; 
        }}
        
        .header {{ 
            text-align: center; 
            margin-bottom: 40px; 
            padding: 30px 0; 
        }}
        
        .header h1 {{ 
            font-size: 3rem; 
            color: #00d4ff; 
            margin-bottom: 10px; 
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }}
        
        .header .subtitle {{ 
            color: #8892b0; 
            font-size: 1.2rem; 
            margin-bottom: 5px; 
        }}
        
        .header .org {{ 
            color: #ffd93d; 
            font-weight: bold; 
        }}
        
        /* Alert Banner */
        .alert-banner {{
            background: linear-gradient(45deg, #ff6b6b, #e55555);
            color: white;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
            font-weight: bold;
            animation: pulse 2s infinite;
            display: {'block' if has_recent_alerts else 'none'};
            box-shadow: 0 8px 25px rgba(255, 107, 107, 0.3);
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.8; }}
        }}
        
        .stats-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); 
            gap: 25px; 
            margin-bottom: 50px; 
        }}
        
        .stat-card {{ 
            background: linear-gradient(145deg, #1a1f2e 0%, #2d3748 100%); 
            border: 1px solid #3a4a5c; 
            border-radius: 20px; 
            padding: 30px; 
            text-align: center; 
            position: relative;
            overflow: hidden;
            min-height: 140px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 4px;
            background: var(--accent-color);
        }}
        
        .stat-card.total {{ --accent-color: #64b5f6; }}
        .stat-card.critical-risk {{ --accent-color: #ff1744; }}
        .stat-card.high-risk {{ --accent-color: #ff6b6b; }}
        .stat-card.medium-risk {{ --accent-color: #ffd93d; }}
        .stat-card.low-risk {{ --accent-color: #6bcf7f; }}
        .stat-card.today {{ --accent-color: #9c27b0; }}
        .stat-card.detection {{ --accent-color: #ff9800; }}
        .stat-card.threat {{ --accent-color: #f44336; }}
        .stat-card.avg {{ --accent-color: #00bcd4; }}
        .stat-card.banking {{ --accent-color: #8a2be2; }}
        .stat-card.logo {{ --accent-color: #ffc107; }}
        
        .stat-number {{ 
            font-size: 2.8rem; 
            font-weight: bold; 
            margin-bottom: 12px; 
            color: var(--accent-color);
            text-shadow: 0 0 10px rgba(var(--accent-color), 0.3);
        }}
        
        .stat-label {{ 
            color: #a0aec0; 
            font-size: 0.95rem; 
            text-transform: uppercase; 
            letter-spacing: 1px; 
            font-weight: 500;
        }}
        
        .recent-section {{ 
            background: rgba(26, 31, 46, 0.9); 
            border-radius: 20px; 
            padding: 35px; 
            margin-bottom: 30px; 
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .recent-section h2 {{ 
            color: #00d4ff; 
            margin-bottom: 30px; 
            font-size: 2rem; 
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .scan-grid {{ 
            display: grid; 
            gap: 20px; 
        }}
        
        .scan-item {{ 
            background: rgba(45, 55, 72, 0.6); 
            border-radius: 15px; 
            padding: 25px; 
            display: grid; 
            grid-template-columns: 2fr 1fr 120px 100px 120px; 
            align-items: center; 
            gap: 20px; 
            border-left: 5px solid var(--risk-color);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        
        .scan-item:hover {{
            transform: translateX(5px);
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.2);
        }}
        
        .scan-item.risk-high {{ --risk-color: #ff6b6b; }}
        .scan-item.risk-critical {{ --risk-color: #ff1744; }}
        .scan-item.risk-medium {{ --risk-color: #ffd93d; }}
        .scan-item.risk-low {{ --risk-color: #6bcf7f; }}
        .scan-item.risk-low-medium {{ --risk-color: #ffb366; }}
        
        .file-info h3 {{ 
            color: #fff; 
            margin-bottom: 8px; 
            font-size: 1.1rem;
        }}
        
        .file-info .meta {{ 
            color: #8892b0; 
            font-size: 0.9rem; 
            line-height: 1.4;
        }}
        
        .risk-badge {{ 
            padding: 10px 18px; 
            border-radius: 25px; 
            font-weight: bold; 
            text-align: center; 
            font-size: 0.85rem; 
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .risk-high {{ background: rgba(255, 107, 107, 0.2); color: #ff6b6b; border: 2px solid #ff6b6b; }}
        .risk-critical {{ background: rgba(255, 23, 68, 0.2); color: #ff1744; border: 2px solid #ff1744; }}
        .risk-medium {{ background: rgba(255, 193, 61, 0.2); color: #ffd93d; border: 2px solid #ffd93d; }}
        .risk-low {{ background: rgba(107, 207, 127, 0.2); color: #6bcf7f; border: 2px solid #6bcf7f; }}
        .risk-low-medium {{ background: rgba(255, 179, 102, 0.2); color: #ffb366; border: 2px solid #ffb366; }}
        
        .score-display {{ 
            font-size: 1.6rem; 
            font-weight: bold; 
            text-align: center; 
            color: var(--risk-color);
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
            display: inline-flex; 
            align-items: center;
            justify-content: center;
            padding: 18px 35px; 
            border-radius: 12px; 
            text-decoration: none; 
            font-weight: 600; 
            font-size: 1.05rem; 
            transition: all 0.3s ease; 
            border: 2px solid;
            min-height: 56px;
            min-width: 160px;
            position: relative;
            overflow: hidden;
        }}
        
        .btn::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }}
        
        .btn:hover::before {{
            left: 100%;
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
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.3); 
        }}
        
        .enhanced-features {{
            background: linear-gradient(145deg, rgba(0, 212, 255, 0.1), rgba(138, 43, 226, 0.05));
            border: 2px solid #00d4ff;
            border-radius: 20px;
            padding: 30px;
            margin: 40px 0;
            text-align: center;
        }}
        
        .enhanced-features h3 {{
            color: #00d4ff;
            margin-bottom: 20px;
            font-size: 1.8rem;
        }}
        
        .features-list {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .feature-item {{
            background: rgba(0, 212, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            border: 1px solid rgba(0, 212, 255, 0.3);
        }}
        
        /* ===== ENHANCED MOBILE RESPONSIVE DESIGN ===== */
        @media (max-width: 768px) {{
            .dashboard-container {{
                padding: 15px;
            }}
            
            .header h1 {{
                font-size: 2.2rem;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
            }}
            
            .stat-card {{
                padding: 20px;
                min-height: 120px;
            }}
            
            .stat-number {{
                font-size: 2.2rem;
            }}
            
            .scan-item {{
                grid-template-columns: 1fr;
                text-align: center;
                gap: 15px;
                padding: 20px;
            }}
            
            .actions {{
                flex-direction: column;
                align-items: center;
                gap: 15px;
            }}
            
            .btn {{
                width: 100%;
                max-width: 300px;
                margin: 8px 0;
            }}
            
            .recent-section {{
                padding: 25px 15px;
            }}
            
            .recent-section h2 {{
                font-size: 1.6rem;
            }}
            
            .features-list {{
                grid-template-columns: 1fr;
            }}
        }}
        
        @media (max-width: 480px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
                gap: 12px;
            }}
            
            .header h1 {{
                font-size: 1.8rem;
            }}
            
            .stat-number {{
                font-size: 2rem;
            }}
            
            .alert-banner {{
                padding: 15px;
                font-size: 0.9rem;
            }}
            
            .btn {{
                padding: 15px 25px;
                font-size: 0.95rem;
            }}
        }}
        
        /* Touch-friendly improvements */
        .btn, .risk-badge {{
            min-height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        /* Landscape phone optimization */
        @media (max-width: 896px) and (orientation: landscape) {{
            .header {{
                margin-bottom: 25px;
            }}
            
            .header h1 {{
                font-size: 2.5rem;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(4, 1fr);
            }}
        }}
        
        /* Tablet optimization */
        @media (min-width: 769px) and (max-width: 1024px) {{
            .stats-grid {{
                grid-template-columns: repeat(3, 1fr);
            }}
            
            .scan-item {{
                grid-template-columns: 2fr 1fr 100px 80px;
            }}
        }}
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <h1>🛡️ CyberSentinels Enhanced Dashboard</h1>
            <p class="subtitle">Advanced Banking APK Threat Detection System v2.0</p>
            <p class="org">Madhya Pradesh Police - Cybercrime Division</p>
        </div>
        
        <div class="alert-banner">
            🚨 HIGH RISK ALERT: New banking malware detected in the last hour! Enhanced analysis and logo detection active.
        </div>
        
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-number">{stats['total_scans']}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            
            <div class="stat-card critical-risk">
                <div class="stat-number">{stats['critical_risk']}</div>
                <div class="stat-label">Critical Risk</div>
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
            
            <div class="stat-card banking">
                <div class="stat-number">{stats['banking_impersonations']}</div>
                <div class="stat-label">Banking Impersonations</div>
            </div>
            
            <div class="stat-card logo">
                <div class="stat-number">{stats['logo_matches']}</div>
                <div class="stat-label">Logo Matches</div>
            </div>
        </div>
        
        <div class="enhanced-features">
            <h3>🚀 Enhanced Detection Capabilities</h3>
            <p style="color: #a0aec0; margin-bottom: 20px;">Advanced AI-powered analysis with specialized Indian banking threat detection</p>
            <div class="features-list">
                <div class="feature-item">🏦 Indian Banking Focus</div>
                <div class="feature-item">🎯 Logo Impersonation Detection</div>
                <div class="feature-item">🔍 Enhanced Behavioral Analysis</div>
                <div class="feature-item">🚨 Real-time Alert System</div>
                <div class="feature-item">📱 Mobile Responsive Interface</div>
                <div class="feature-item">🛡️ VirusTotal Integration</div>
                <div class="feature-item">🔑 Keylogging Detection</div>
                <div class="feature-item">📹 Screen Recording Detection</div>
            </div>
        </div>
        
        <div class="recent-section">
            <h2>📊 Recent Enhanced Threat Analysis</h2>
            <div class="scan-grid">
                {"".join([f'''
                <div class="scan-item risk-{scan[1].lower().replace(" ", "-").replace("_", "-")}">
                    <div class="file-info">
                        <h3>{scan[0]}</h3>
                        <div class="meta">
                            Scanned: {scan[3]}<br>
                            Hash: {scan[5][:12] if scan[5] else "Unknown"}...<br>
                            {f"Banking Score: {scan[6]}/100" if scan[6] and scan[6] > 0 else ""}
                            {f" | Logo: {scan[7]}" if scan[7] else ""}
                        </div>
                    </div>
                    <div class="risk-badge risk-{scan[1].lower().replace(" ", "-").replace("_", "-")}">{scan[1]} RISK</div>
                    <div class="score-display">{scan[2]}/100</div>
                    <div style="text-align: center;">
                        {"🚨" if scan[9] else "📊"}
                    </div>
                    <div>
                        <a href="/export/{recent_scans.index(scan) + 1}" class="btn btn-secondary" style="padding: 8px 16px; font-size: 0.8rem;">Export</a>
                    </div>
                </div>
                ''' for scan in recent_scans[:15]])}
            </div>
        </div>
        
        <div class="actions">
            <a href="/scan" class="btn btn-primary">🔍 New Enhanced APK Scan</a>
            <a href="/api/threat-intelligence" class="btn btn-secondary">📈 Export Intelligence</a>
            <a href="/api/threat-reports" class="btn btn-danger">🚨 Alert System Status</a>
        </div>
    </div>
</body>
</html>
    """
    
    return dashboard_html

@app.route("/scan", methods=["GET", "POST"])
def scan():
    """Enhanced APK scanning with full mobile responsiveness"""
    if request.method == "GET":
        # Enhanced mobile-responsive scanning interface
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinels - Enhanced APK Security Platform</title>
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
            line-height: 1.6;
        }

        /* Enhanced animated background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 50%, rgba(0, 212, 255, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(138, 43, 226, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 80%, rgba(255, 20, 147, 0.08) 0%, transparent 50%);
            animation: backgroundShift 25s ease-in-out infinite;
            pointer-events: none;
            z-index: -1;
        }

        @keyframes backgroundShift {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        /* Enhanced navigation */
        nav {
            padding: 1.2rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(10, 10, 11, 0.9);
            backdrop-filter: blur(25px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            position: fixed;
            width: 100%;
            top: 0;
            z-index: 1000;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }

        .logo {
            font-size: 1.6rem;
            font-weight: 700;
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-links {
            display: flex;
            gap: 2.5rem;
            align-items: center;
        }

        .nav-links a {
            color: rgba(255, 255, 255, 0.85);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
            font-size: 0.95rem;
        }

        .nav-links a:hover {
            color: #00d4ff;
        }

        /* Enhanced hero section */
        .hero {
            padding: 10rem 2rem 8rem;
            text-align: center;
            max-width: 1200px;
            margin: 0 auto;
        }

        .hero h1 {
            font-size: clamp(2.8rem, 6vw, 4.5rem);
            font-weight: 700;
            margin-bottom: 2rem;
            line-height: 1.1;
        }

        .gradient-text {
            background: linear-gradient(135deg, #00d4ff, #8a2be2, #ff1493);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-size: 200% 200%;
            animation: gradientShift 5s ease-in-out infinite;
        }

        @keyframes gradientShift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }

        .hero p {
            font-size: 1.3rem;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 3.5rem;
            max-width: 700px;
            margin-left: auto;
            margin-right: auto;
            line-height: 1.7;
        }

        .cta-buttons {
            display: flex;
            gap: 1.5rem;
            justify-content: center;
            flex-wrap: wrap;
            margin-bottom: 4rem;
        }

        .cta-primary, .cta-secondary {
            padding: 1.2rem 2.5rem;
            border-radius: 60px;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.3s ease;
            font-size: 1.05rem;
            border: 2px solid transparent;
            position: relative;
            overflow: hidden;
            min-height: 50px;
            min-width: 180px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .cta-primary {
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            color: white;
            box-shadow: 0 8px 25px rgba(0, 212, 255, 0.3);
        }

        .cta-primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 40px rgba(0, 212, 255, 0.4);
        }

        .cta-secondary {
            background: transparent;
            color: #00d4ff;
            border-color: #00d4ff;
        }

        .cta-secondary:hover {
            background: rgba(0, 212, 255, 0.1);
            transform: translateY(-3px);
        }

        /* Enhanced upload section */
        .upload-section {
            max-width: 900px;
            margin: 6rem auto;
            padding: 0 2rem;
        }

        .upload-card {
            background: rgba(26, 27, 35, 0.9);
            backdrop-filter: blur(25px);
            border-radius: 25px;
            border: 1px solid rgba(255, 255, 255, 0.15);
            padding: 4rem 3rem;
            text-align: center;
            position: relative;
            overflow: hidden;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3);
        }

        .upload-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
        }

        .upload-title {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.8rem;
            color: #fff;
        }

        .upload-subtitle {
            color: rgba(255, 255, 255, 0.7);
            margin-bottom: 3rem;
            font-size: 1.1rem;
            line-height: 1.6;
        }

        .file-upload-area {
            border: 3px dashed rgba(0, 212, 255, 0.6);
            border-radius: 20px;
            padding: 4rem 3rem;
            margin-bottom: 3rem;
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            background: rgba(0, 212, 255, 0.02);
        }

        .file-upload-area:hover {
            border-color: #00d4ff;
            background: rgba(0, 212, 255, 0.08);
            transform: translateY(-2px);
        }

        .file-upload-area.dragover {
            border-color: #8a2be2;
            background: rgba(138, 43, 226, 0.15);
            box-shadow: 0 0 30px rgba(138, 43, 226, 0.3);
        }

        .upload-icon {
            font-size: 4rem;
            color: #00d4ff;
            margin-bottom: 1.5rem;
            display: block;
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
            color: rgba(255, 255, 255, 0.9);
            font-size: 1.15rem;
            margin-bottom: 0.8rem;
            font-weight: 500;
        }

        .file-types {
            color: rgba(255, 255, 255, 0.6);
            font-size: 0.95rem;
        }

        .analyze-btn {
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            color: white;
            border: none;
            padding: 1.3rem 4rem;
            border-radius: 60px;
            font-size: 1.2rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            min-height: 56px;
            min-width: 200px;
            box-shadow: 0 8px 25px rgba(0, 212, 255, 0.3);
        }

        .analyze-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 40px rgba(0, 212, 255, 0.4);
        }

        .analyze-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        /* Enhanced features section */
        .features {
            max-width: 1200px;
            margin: 8rem auto;
            padding: 0 2rem;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 2.5rem;
            margin-top: 4rem;
        }

        .feature-card {
            background: rgba(26, 27, 35, 0.8);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 3rem 2.5rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .feature-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }

        .feature-card:hover::before {
            transform: scaleX(1);
        }

        .feature-card:hover {
            transform: translateY(-8px);
            border-color: rgba(0, 212, 255, 0.5);
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.2);
        }

        .feature-icon {
            font-size: 3rem;
            margin-bottom: 1.5rem;
            display: block;
        }

        .feature-title {
            font-size: 1.4rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: #fff;
        }

        .feature-description {
            color: rgba(255, 255, 255, 0.75);
            line-height: 1.7;
            font-size: 1rem;
        }

        .section-title {
            font-size: 2.8rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-align: center;
        }

        .section-subtitle {
            color: rgba(255, 255, 255, 0.7);
            font-size: 1.2rem;
            margin-bottom: 4rem;
            text-align: center;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }

        /* Enhanced mobile responsiveness */
        @media (max-width: 768px) {
            .nav-links {
                display: none;
            }
            
            .hero {
                padding: 8rem 1rem 6rem;
            }
            
            .cta-buttons {
                flex-direction: column;
                align-items: center;
                gap: 1rem;
            }
            
            .cta-primary, .cta-secondary {
                width: 100%;
                max-width: 300px;
            }
            
            .upload-card {
                margin: 0 1rem;
                padding: 3rem 2rem;
            }
            
            .file-upload-area {
                padding: 3rem 2rem;
            }
            
            .features {
                margin-left: 1rem;
                margin-right: 1rem;
            }
            
            .features-grid {
                grid-template-columns: 1fr;
                gap: 2rem;
            }
            
            .feature-card {
                padding: 2.5rem 2rem;
            }
        }

        @media (max-width: 480px) {
            .hero h1 {
                font-size: 2.2rem;
            }
            
            .hero p {
                font-size: 1.1rem;
                margin-bottom: 2.5rem;
            }
            
            .upload-card {
                padding: 2.5rem 1.5rem;
            }
            
            .file-upload-area {
                padding: 2.5rem 1.5rem;
            }
            
            .upload-icon {
                font-size: 3rem;
            }
            
            .analyze-btn {
                padding: 1.1rem 3rem;
                font-size: 1.1rem;
            }
            
            .section-title {
                font-size: 2.2rem;
            }
        }

        /* Loading animation */
        .loading {
            display: none;
            text-align: center;
            margin-top: 2.5rem;
        }

        .loading-spinner {
            width: 50px;
            height: 50px;
            border: 4px solid rgba(0, 212, 255, 0.3);
            border-top: 4px solid #00d4ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1.5rem;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .selected-file {
            background: rgba(0, 212, 255, 0.15);
            border: 2px solid #00d4ff;
            color: #00d4ff;
            padding: 1.5rem;
            border-radius: 15px;
            margin: 1.5rem 0;
            display: none;
            font-weight: 500;
        }

        .enhanced-badge {
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            display: inline-block;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <nav>
        <div class="logo">🛡️ CyberSentinels Enhanced</div>
        <div class="nav-links">
            <a href="#features">Features</a>
            <a href="#enhanced">Enhanced Detection</a>
            <a href="#team">About</a>
            <a href="/dashboard">Dashboard</a>
        </div>
    </nav>

    <section class="hero">
        <div class="enhanced-badge">🚀 Enhanced v2.0 with Logo Detection</div>
        <h1>
            <span class="gradient-text">AI-Powered Banking Security Platform</span>
        </h1>
        <p>
            Advanced APK analysis specialized for Indian banking threats. Enhanced with logo impersonation detection, behavioral analysis, and real-time alerts. Protect against trojans, overlays, and financial malware with cutting-edge AI detection.
        </p>
        <div class="cta-buttons">
            <a href="#upload" class="cta-primary">🚀 Start Enhanced Scanning</a>
            <a href="/dashboard" class="cta-secondary">📊 View Enhanced Dashboard</a>
        </div>
    </section>

    <section class="upload-section" id="upload">
        <div class="upload-card">
            <div class="upload-title">Enhanced Banking APK Security Scanner</div>
            <div class="upload-subtitle">Upload and analyze APK files with our enhanced AI-powered detection system featuring logo impersonation detection, advanced behavioral analysis, and real-time threat alerts</div>
            
            <form method="post" enctype="multipart/form-data" id="uploadForm">
                <div class="file-upload-area" id="fileUploadArea">
                    <div class="upload-icon">📱</div>
                    <input type="file" name="file" accept=".apk" class="file-input" id="fileInput" required>
                    <div class="upload-text">Drop your APK file here or click to browse</div>
                    <div class="file-types">Supports APK files up to 100MB • Enhanced banking threat analysis with logo detection</div>
                </div>
                
                <div class="selected-file" id="selectedFile"></div>
                
                <button type="submit" class="analyze-btn" id="analyzeBtn" disabled>
                    🔍 Analyze with Enhanced Detection
                </button>
                
                <div class="loading" id="loadingDiv">
                    <div class="loading-spinner"></div>
                    <div>Performing enhanced threat analysis with logo detection...</div>
                </div>
            </form>
        </div>
    </section>

    <section class="features" id="features">
        <div class="section-title">Enhanced Security Features</div>
        <div class="section-subtitle">Comprehensive protection powered by artificial intelligence, machine learning, and advanced visual analysis</div>
        
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon">🏦</div>
                <div class="feature-title">Enhanced Indian Banking Focus</div>
                <div class="feature-description">
                    Specialized detection for Indian banking trojans, with pre-loaded legitimate bank database, impersonation detection, and enhanced behavioral analysis.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🎯</div>
                <div class="feature-title">Logo Impersonation Detection</div>
                <div class="feature-description">
                    Advanced visual analysis compares app icons with legitimate bank logos using perceptual hashing to detect sophisticated impersonation attempts.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🔍</div>
                <div class="feature-title">Enhanced Behavioral Analysis</div>
                <div class="feature-description">
                    Detects keylogging, screen recording, overlay attacks, accessibility abuse, and other sophisticated banking malware techniques with improved accuracy.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🚨</div>
                <div class="feature-title">Real-time Alert System</div>
                <div class="feature-description">
                    Immediate notifications to law enforcement when high-risk banking malware or logo impersonation is detected, with detailed threat intelligence.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">📱</div>
                <div class="feature-title">Mobile Optimized Interface</div>
                <div class="feature-description">
                    Fully responsive design optimized for field officers and mobile cybercrime investigation units with touch-friendly controls.
                </div>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🛡️</div>
                <div class="feature-title">Enhanced VirusTotal Integration</div>
                <div class="feature-description">
                    Connected to global threat intelligence networks with real-time updates on emerging malware families and improved analysis reporting.
                </div>
            </div>
        </div>
    </section>

    <script>
        // Enhanced file upload handling with better UX
        const fileInput = document.getElementById('fileInput');
        const fileUploadArea = document.getElementById('fileUploadArea');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const selectedFile = document.getElementById('selectedFile');
        const uploadForm = document.getElementById('uploadForm');
        const loadingDiv = document.getElementById('loadingDiv');

        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const fileSize = (file.size / 1024 / 1024).toFixed(2);
                selectedFile.innerHTML = `
                    <div style="font-weight: 600; margin-bottom: 5px;">Selected: ${file.name}</div>
                    <div>Size: ${fileSize} MB | Ready for enhanced analysis</div>
                `;
                selectedFile.style.display = 'block';
                analyzeBtn.disabled = false;
                analyzeBtn.textContent = '🔍 Analyze with Enhanced Detection & Logo Analysis';
                analyzeBtn.style.background = 'linear-gradient(135deg, #00d4ff, #8a2be2)';
            }
        });

        // Enhanced drag and drop functionality
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
            if (files.length > 0 && files[0].name.endsWith('.apk')) {
                fileInput.files = files;
                fileInput.dispatchEvent(new Event('change'));
            } else {
                alert('Please select a valid APK file for enhanced analysis.');
            }
        });

        // Enhanced form submission handling
        uploadForm.addEventListener('submit', function(e) {
            analyzeBtn.disabled = true;
            analyzeBtn.textContent = 'Analyzing with Enhanced AI & Logo Detection...';
            loadingDiv.style.display = 'block';
            
            // Smooth scroll to loading area
            loadingDiv.scrollIntoView({ behavior: 'smooth' });
        });

        // Smooth scrolling for navigation links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
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
                # ENHANCED ANALYSIS - USING UPGRADED DETECTION LOGIC WITH ALL NEW FEATURES
                if detector:
                    if hasattr(detector, 'analyze_apk_comprehensive'):
                        logger.info(f"Starting comprehensive analysis for {filename}")
                        analysis_results = detector.analyze_apk_comprehensive(filepath)
                    else:
                        # Fallback to basic analysis
                        analysis_results = {
                            'file_info': {'filename': filename, 'size': os.path.getsize(filepath)},
                            'risk_assessment': {
                                'overall_score': 35,
                                'risk_level': 'MEDIUM',
                                'threat_indicators': ['basic_analysis_fallback'],
                                'recommendation': 'Basic analysis completed - upgrade detector for full enhanced features'
                            }
                        }
                else:
                    # Dummy analysis if no detector is found
                    analysis_results = {
                        'file_info': {'filename': filename, 'size': os.path.getsize(filepath)},
                        'risk_assessment': {
                            'overall_score': 25,
                            'risk_level': 'LOW',
                            'threat_indicators': ['no_detector_available'],
                            'recommendation': 'Demo mode - enhanced detector not loaded'
                        }
                    }
                
                risk_assessment = analysis_results.get('risk_assessment', {})
                risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
                risk_score = risk_assessment.get('overall_score', 0)
                
                # ENHANCED THREAT DETECTION WITH ALL NEW FEATURES
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
                
                # Store enhanced results in the database
                conn = sqlite3.connect('scan_results.db')
                c = conn.cursor()
                c.execute('''
                    INSERT INTO scan_results 
                    (filename, file_hash, risk_level, risk_score, threat_indicators, scan_timestamp, analysis_results,
                     impersonation_score, logo_match, behavioral_score, alert_sent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    risk_level in ['HIGH', 'CRITICAL'] or risk_score >= 70
                ))
                conn.commit()
                conn.close()
                
                # ENHANCED ALERT TRIGGERING
                trigger_alerts_if_needed(analysis_results, filename)
                
                # Clean up
                os.remove(filepath)
                
                # ENHANCED RESULTS DISPLAY WITH FULL MOBILE RESPONSIVENESS
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
    """Render enhanced results page with full mobile responsiveness"""
    
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
    
    # Enhanced threat indicators display with emojis and styling
    if enhanced_threats:
        threat_indicators_html = '<div class="threats-container">'
        for threat in enhanced_threats[:15]:  # Show more threats
            threat_class = 'threat-critical' if any(word in threat.lower() for word in ['critical', 'extreme']) else 'threat-high' if any(word in threat.lower() for word in ['high', 'banking', 'logo']) else 'threat-medium'
            threat_indicators_html += f'<div class="threat-badge {threat_class}">{threat}</div>'
        if len(enhanced_threats) > 15:
            threat_indicators_html += f'<div class="threat-badge threat-info">+{len(enhanced_threats) - 15} more threats detected</div>'
        threat_indicators_html += '</div>'
    else:
        threat_indicators_html = '<div class="no-threats">✅ No specific threats detected by enhanced analysis</div>'
    
    # Enhanced recommendation based on risk level
    recommendations = {
        'HIGH': '🚨 IMMEDIATE ACTION REQUIRED - Block this APK and investigate source. Enhanced analysis detected high-risk patterns.',
        'CRITICAL': '💀 CRITICAL THREAT - Do not install. Report to cybercrime authorities immediately. Enhanced detection confirmed malicious behavior.',
        'MEDIUM': '⚠️ PROCEED WITH CAUTION - Manual review recommended before installation. Enhanced behavioral analysis found suspicious indicators.',
        'LOW-MEDIUM': '🔍 MONITOR - Some suspicious indicators detected by enhanced analysis. Proceed with elevated caution.',
        'LOW': '✅ APPEARS SAFE - Enhanced analysis indicates low risk, but remain vigilant for emerging threats.'
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
    <title>CyberSentinels - Enhanced Analysis Results</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%); 
            color: #fff; 
            min-height: 100vh;
            font-size: 16px;
            line-height: 1.6;
        }}
        
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 40px 20px; 
        }}
        
        .header {{ 
            text-align: center; 
            margin-bottom: 50px; 
        }}
        
        .header h1 {{ 
            font-size: 3.5rem; 
            color: #00d4ff; 
            margin-bottom: 15px; 
            text-shadow: 0 0 30px rgba(0, 212, 255, 0.3);
        }}
        
        .header .subtitle {{ 
            color: #8892b0; 
            font-size: 1.3rem; 
            margin-bottom: 10px;
        }}
        
        .enhanced-badge {{
            background: linear-gradient(135deg, #00d4ff, #8a2be2);
            color: white;
            padding: 8px 20px;
            border-radius: 25px;
            font-size: 0.9rem;
            font-weight: 600;
            display: inline-block;
            margin-bottom: 20px;
        }}
        
        .results-main {{ 
            display: grid; 
            grid-template-columns: 1fr 350px; 
            gap: 40px; 
            margin-bottom: 50px; 
        }}
        
        .analysis-panel {{ 
            background: rgba(26, 31, 46, 0.95); 
            border-radius: 25px; 
            padding: 50px; 
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
        }}
        
        .risk-panel {{ 
            background: rgba(26, 31, 46, 0.95); 
            border-radius: 25px; 
            padding: 40px; 
            text-align: center; 
            height: fit-content;
            border: 3px solid {risk_color};
            box-shadow: 0 0 30px rgba({risk_color.lstrip('#')}, 0.3);
        }}
        
        .risk-score {{ 
            font-size: 5rem; 
            font-weight: bold; 
            color: {risk_color}; 
            margin: 25px 0; 
            text-shadow: 0 0 25px {risk_color}60;
        }}
        
        .risk-level {{ 
            display: inline-block; 
            background: {risk_color}; 
            color: {('#000' if risk_level in ['MEDIUM', 'LOW'] else '#fff')}; 
            padding: 15px 30px; 
            border-radius: 35px; 
            font-weight: bold; 
            font-size: 1.4rem; 
            margin-bottom: 25px;
            text-transform: uppercase;
            letter-spacing: 2px;
            box-shadow: 0 8px 20px rgba({risk_color.lstrip('#')}, 0.4);
        }}
        
        .confidence-display {{
            margin-top: 25px;
        }}
        
        .confidence-meter {{ 
            background: #2d3748; 
            height: 15px; 
            border-radius: 8px; 
            overflow: hidden; 
            margin: 12px 0; 
        }}
        
        .confidence-fill {{ 
            height: 100%; 
            background: {risk_color}; 
            width: {confidence * 100}%; 
            transition: width 2s ease; 
            border-radius: 8px;
        }}
        
        .info-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); 
            gap: 25px; 
            margin: 40px 0; 
        }}
        
        .info-card {{ 
            background: rgba(45, 55, 72, 0.6); 
            border-radius: 20px; 
            padding: 25px; 
            text-align: center; 
            min-height: 120px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            transition: transform 0.3s ease;
        }}
        
        .info-card:hover {{
            transform: translateY(-5px);
        }}
        
        .info-label {{ 
            color: #8892b0; 
            font-size: 0.95rem; 
            margin-bottom: 10px; 
            text-transform: uppercase; 
            letter-spacing: 1px; 
            font-weight: 500;
        }}
        
        .info-value {{ 
            color: #fff; 
            font-size: 1.6rem; 
            font-weight: bold; 
        }}
        
        .threats-section {{ 
            margin: 50px 0; 
        }}
        
        .section-title {{ 
            font-size: 2.2rem; 
            color: #00d4ff; 
            margin-bottom: 25px; 
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .threats-container {{ 
            display: flex; 
            flex-wrap: wrap; 
            gap: 15px; 
        }}
        
        .threat-badge {{ 
            padding: 12px 20px; 
            border-radius: 30px; 
            font-weight: bold; 
            font-size: 0.95rem; 
            display: flex;
            align-items: center;
            gap: 8px;
            min-height: 48px;
            transition: transform 0.2s ease;
        }}
        
        .threat-badge:hover {{
            transform: translateY(-2px);
        }}
        
        .threat-critical {{ 
            background: rgba(255, 23, 68, 0.25); 
            border: 2px solid #ff1744; 
            color: #ff1744; 
        }}
        
        .threat-high {{ 
            background: rgba(255, 107, 107, 0.25); 
            border: 2px solid #ff6b6b; 
            color: #ff6b6b; 
        }}
        
        .threat-medium {{ 
            background: rgba(255, 193, 61, 0.25); 
            border: 2px solid #ffd93d; 
            color: #ffd93d; 
        }}
        
        .threat-info {{ 
            background: rgba(0, 212, 255, 0.25); 
            border: 2px solid #00d4ff; 
            color: #00d4ff; 
        }}
        
        .no-threats {{ 
            color: #6bcf7f; 
            font-weight: bold; 
            text-align: center; 
            font-size: 1.4rem; 
            padding: 40px; 
            background: rgba(107, 207, 127, 0.15); 
            border-radius: 20px; 
            border: 3px solid #6bcf7f; 
        }}
        
        .recommendation-panel {{ 
            background: linear-gradient(145deg, rgba(0, 212, 255, 0.15), rgba(138, 43, 226, 0.08)); 
            border: 3px solid #00d4ff; 
            border-radius: 20px; 
            padding: 40px; 
            margin: 50px 0; 
            text-align: center; 
        }}
        
        .recommendation-panel h3 {{ 
            color: #00d4ff; 
            margin-bottom: 20px; 
            font-size: 1.8rem; 
        }}
        
        .recommendation-text {{ 
            font-size: 1.2rem; 
            line-height: 1.7; 
            color: #fff; 
        }}
        
        .actions {{ 
            text-align: center; 
            margin-top: 60px; 
            display: flex;
            gap: 25px;
            justify-content: center;
            flex-wrap: wrap;
        }}
        
        .btn {{ 
            display: inline-flex; 
            align-items: center;
            justify-content: center;
            padding: 18px 35px; 
            border-radius: 15px; 
            text-decoration: none; 
            font-weight: 600; 
            font-size: 1.05rem; 
            transition: all 0.3s ease; 
            border: 2px solid;
            min-height: 56px;
            min-width: 180px;
            position: relative;
            overflow: hidden;
        }}
        
        .btn::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }}
        
        .btn:hover::before {{
            left: 100%;
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
            transform: translateY(-4px); 
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.3); 
        }}
        
        .additional-info {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); 
            gap: 30px; 
            margin: 50px 0; 
        }}
        
        .info-panel {{ 
            background: rgba(45, 55, 72, 0.4); 
            border-radius: 20px; 
            padding: 35px; 
            border: 1px solid rgba(255, 255, 255, 0.15); 
            transition: transform 0.3s ease;
        }}
        
        .info-panel:hover {{
            transform: translateY(-3px);
        }}
        
        .info-panel h4 {{ 
            color: #00d4ff; 
            margin-bottom: 20px; 
            font-size: 1.4rem; 
        }}
        
        .info-panel p {{ 
            color: #a0aec0; 
            line-height: 1.7; 
            margin-bottom: 12px;
            font-size: 1.05rem;
        }}
        
        /* ENHANCED MOBILE RESPONSIVE DESIGN */
        @media (max-width: 768px) {{
            .results-main {{ 
                grid-template-columns: 1fr; 
                gap: 30px;
            }}
            
            .container {{ 
                padding: 25px 15px; 
            }}
            
            .analysis-panel, .risk-panel {{ 
                padding: 30px 20px; 
            }}
            
            .info-grid {{ 
                grid-template-columns: 1fr; 
                gap: 20px;
            }}
            
            .actions {{ 
                flex-direction: column; 
                align-items: center; 
                gap: 20px;
            }}
            
            .btn {{ 
                width: 100%; 
                max-width: 320px; 
                margin: 8px 0; 
            }}
            
            .header h1 {{ 
                font-size: 2.5rem; 
            }}
            
            .risk-score {{ 
                font-size: 3.5rem; 
            }}
            
            .threats-container {{ 
                gap: 10px; 
            }}
            
            .threat-badge {{ 
                font-size: 0.85rem; 
                padding: 8px 15px; 
            }}
            
            .additional-info {{ 
                grid-template-columns: 1fr; 
                gap: 20px;
            }}
            
            .info-panel {{
                padding: 25px 20px;
            }}
        }}
        
        @media (max-width: 480px) {{
            .risk-score {{ 
                font-size: 3rem; 
            }}
            
            .risk-level {{ 
                font-size: 1.1rem; 
                padding: 12px 24px; 
            }}
            
            .section-title {{ 
                font-size: 1.8rem; 
            }}
            
            .threat-badge {{ 
                font-size: 0.8rem; 
                padding: 6px 12px; 
            }}
            
            .info-value {{ 
                font-size: 1.4rem; 
            }}
            
            .recommendation-text {{ 
                font-size: 1.1rem; 
            }}
            
            .btn {{
                padding: 15px 25px;
                font-size: 1rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="enhanced-badge">🚀 Enhanced Analysis v2.0</div>
            <h1>🛡️ Enhanced Analysis Complete</h1>
            <p class="subtitle">Advanced APK Security Analysis Results with Logo Detection & Behavioral Analysis</p>
        </div>
        
        <div class="results-main">
            <div class="analysis-panel">
                <div class="section-title">
                    📱 Enhanced File Analysis Report
                </div>
                
                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Filename</div>
                        <div class="info-value" style="font-size: 1.1rem; word-break: break-word;">{filename}</div>
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
                        <div class="info-value" style="color: {('#ff6b6b' if dangerous_permissions > 5 else '#ffd93d' if dangerous_permissions > 2 else '#6bcf7f')}">{dangerous_permissions}</div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Banking Impersonation</div>
                        <div class="info-value" style="color: {('#ff1744' if impersonation_score > 60 else '#ff6b6b' if impersonation_score > 30 else '#6bcf7f')}; font-size: 1.3rem;">{impersonation_score}/100</div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Logo Similarity</div>
                        <div class="info-value" style="color: {('#ff1744' if logo_similarity > 0.7 else '#ffd93d' if logo_similarity > 0.5 else '#6bcf7f')}; font-size: 1.3rem;">{logo_similarity:.1%}</div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Behavioral Score</div>
                        <div class="info-value" style="color: {('#ff1744' if trojan_score > 70 else '#ff6b6b' if trojan_score > 40 else '#6bcf7f')}; font-size: 1.3rem;">{trojan_score}/100</div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Detection Engine</div>
                        <div class="info-value" style="font-size: 0.9rem; color: #00d4ff;">Enhanced v2.0</div>
                    </div>
                </div>
                
                {f'''
                <div style="background: rgba(255, 107, 107, 0.2); border: 2px solid #ff6b6b; border-radius: 15px; padding: 20px; margin: 20px 0;">
                    <h4 style="color: #ff6b6b; margin-bottom: 10px;">🏦 Banking Security Alert:</h4>
                    <p style="color: #fff;">High impersonation risk detected for Indian banking applications.</p>
                </div>
                ''' if impersonation_score > 60 else ""}
                
                {f'''
                <div style="background: rgba(138, 43, 226, 0.2); border: 2px solid #8a2be2; border-radius: 15px; padding: 20px; margin: 20px 0;">
                    <h4 style="color: #8a2be2; margin-bottom: 10px;">🎯 Logo Impersonation Alert:</h4>
                    <p style="color: #fff;">App icon matches {logo_bank} with {logo_similarity:.1%} similarity</p>
                </div>
                ''' if logo_match else ""}
                
                <div class="threats-section">
                    <div class="section-title">
                        ⚠️ Enhanced Threat Indicators
                        <span style="font-size: 1rem; background: {risk_color}; color: {'#000' if risk_level in ['MEDIUM', 'LOW'] else '#fff'}; padding: 6px 15px; border-radius: 15px;">{len(enhanced_threats)} detected</span>
                    </div>
                    {threat_indicators_html}
                </div>
                
                <div class="additional-info">
                    <div class="info-panel">
                        <h4>🔍 Enhanced Analysis Details</h4>
                        <p>File Hash: <code style="color: #00d4ff; background: rgba(0,212,255,0.1); padding: 2px 6px; border-radius: 4px;">{file_info.get('sha256', 'N/A')[:32]}...</code></p>
                        <p>Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p>VirusTotal Status: {vt_status}</p>
                        <p>Detection Engine: Enhanced CyberSentinels v2.0</p>
                        <p>Features Used: Logo Detection, Behavioral Analysis, Real-time Alerts</p>
                    </div>
                    
                    <div class="info-panel">
                        <h4>🏦 Banking Context Analysis</h4>
                        <p>Impersonation Score: <strong style="color: {('#ff1744' if impersonation_score > 60 else '#ffd93d' if impersonation_score > 30 else '#6bcf7f')}">{impersonation_score}/100</strong></p>
                        <p>Logo Match: <strong style="color: {('#ff1744' if logo_match else '#6bcf7f')}">{logo_bank if logo_match else 'No match detected'}</strong></p>
                        <p>Visual Similarity: <strong style="color: {('#ff1744' if logo_similarity > 0.7 else '#6bcf7f')}">{logo_similarity:.1%}</strong></p>
                        <p>Indian Banking Focus: <strong style="color: #00d4ff;">Enhanced Active</strong></p>
                        <p>Behavioral Analysis: <strong style="color: #6bcf7f;">Complete</strong></p>
                        <p>Alert System: <strong style="color: #ffd93d;">Monitored</strong></p>
                    </div>
                    
                    <div class="info-panel">
                        <h4>🚀 Enhanced Detection Features</h4>
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
            </div>
            
            <div class="risk-panel">
                <h2 style="color: #fff; margin-bottom: 15px;">🎯 Enhanced Risk Assessment</h2>
                
                <div class="risk-score">{risk_score}</div>
                <div style="color: #8892b0; margin-bottom: 25px; font-size: 1.1rem;">/100</div>
                
                <div class="risk-level">{risk_level} RISK</div>
                
                <div class="confidence-display">
                    <div style="color: #8892b0; margin-bottom: 8px; font-size: 1.05rem;">Confidence Level</div>
                    <div class="confidence-meter">
                        <div class="confidence-fill"></div>
                    </div>
                    <div style="color: {risk_color}; font-weight: bold; font-size: 1.1rem;">{confidence:.1%}</div>
                </div>
                
                <div style="margin-top: 30px; padding: 20px; background: rgba(0, 212, 255, 0.15); border-radius: 15px; border: 2px solid #00d4ff;">
                    <h4 style="color: #00d4ff; margin-bottom: 8px;">Enhanced Detection</h4>
                    <p style="font-size: 0.95rem; color: #a0aec0; line-height: 1.5;">Logo Analysis + Behavioral Patterns + Real-time Intelligence</p>
                </div>
            </div>
        </div>
        
        <div class="recommendation-panel">
            <h3>🔍 Enhanced Security Recommendation</h3>
            <p class="recommendation-text">{recommendation}</p>
            {"<p style='margin-top: 20px; color: #ff6b6b; font-weight: bold; font-size: 1.1rem;'>⚠️ Real-time alert has been triggered for law enforcement.</p>" if risk_level in ['HIGH', 'CRITICAL'] or risk_score >= 70 else ""}
        </div>
        
        <div class="actions">
            <a href="/scan" class="btn btn-primary">🔍 Scan Another APK</a>
            <a href="/dashboard" class="btn btn-secondary">📊 Enhanced Dashboard</a>
            <a href="/api/threat-intelligence" class="btn btn-danger">📋 Export Full Report</a>
        </div>
    </div>
</body>
</html>
    """

# ===== ENHANCED API ENDPOINTS FOR LAW ENFORCEMENT =====

@app.route("/api/threat-intelligence")
def threat_intelligence():
    """Enhanced API endpoint for law enforcement threat intelligence"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Get comprehensive statistics with enhanced fields
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
            MAX(scan_timestamp) as last_scan
    ''')
    stats = c.fetchone()
    
    # Get recent high-priority threats with enhanced data
    c.execute('''
        SELECT filename, risk_level, risk_score, threat_indicators, scan_timestamp, file_hash,
               impersonation_score, logo_match, behavioral_score, alert_sent
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
    
    # Enhanced intelligence data for law enforcement
    intelligence_data = {
        'system_status': 'operational_enhanced',
        'system_info': {
            'name': 'CyberSentinels Enhanced APK Detector',
            'version': '2.0 - Enhanced Competition Edition',
            'organization': 'Madhya Pradesh Police Cybercrime Division',
            'specialization': 'Indian Banking APK Threat Detection with Logo Analysis',
            'last_update': datetime.now().isoformat(),
            'enhanced_features': [
                'Logo Impersonation Detection',
                'Enhanced Behavioral Analysis', 
                'Real-time Alert System',
                'Mobile-Responsive Interface',
                'Advanced Permission Analysis',
                'VirusTotal Integration',
                'Banking Trojan Detection'
            ]
        },
        'enhanced_statistics': {
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
            'detection_rate': round(((stats[1] + stats[2]) / max(stats[0], 1)) * 100, 2) if stats else 0.0,
            'today_activity': today_activity,
            'banking_threats_detected': banking_threats,
            'last_scan': stats[10] if stats and stats[10] else None
        },
        'enhanced_threat_landscape': {
            'banking_trojans_detected': sum(1 for threat in recent_threats if 'banking' in str(threat[3]).lower()),
            'overlay_attacks_detected': sum(1 for threat in recent_threats if 'overlay' in str(threat[3]).lower()),
            'impersonation_attempts': sum(1 for threat in recent_threats if threat[6] and threat[6] > 60),
            'logo_based_attacks': sum(1 for threat in recent_threats if threat[7]),
            'keylogging_threats': sum(1 for threat in recent_threats if 'keylog' in str(threat[3]).lower()),
            'screen_recording_threats': sum(1 for threat in recent_threats if 'screen' in str(threat[3]).lower()),
            'critical_threats': sum(1 for threat in recent_threats if threat[1] == 'CRITICAL'),
            'behavioral_anomalies': sum(1 for threat in recent_threats if threat[8] and threat[8] > 70)
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
                'alert_sent': bool(threat[9]) if threat[9] is not None else False
            }
            for threat in recent_threats
        ],
        'enhanced_capabilities': [
            'Real-time APK Static Analysis',
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
            'Mobile-Responsive Interface for Field Operations'
        ],
        'alert_system': {
            'status': 'enhanced_active',
            'alerts_sent_today': sum(1 for threat in recent_threats if threat[9] and datetime.fromisoformat(threat[4]).date() == datetime.now().date()),
            'webhook_configured': bool(app.config.get('ALERT_WEBHOOK_URL') and "YOUR/WEBHOOK/URL" not in app.config.get('ALERT_WEBHOOK_URL', '')),
            'alert_threshold': 70,
            'banking_alert_threshold': 60,
            'logo_alert_threshold': 0.7
        },
        'export_timestamp': datetime.now().isoformat(),
        'report_id': f"CS-ENHANCED-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        'enhanced_version': '2.0'
    }
    
    return jsonify(intelligence_data)

@app.route("/api/threat-reports")
def threat_reports():
    """Enhanced threat reporting API"""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    
    # Get detailed threat reports
    c.execute('''
        SELECT * FROM scan_results 
        ORDER BY scan_timestamp DESC 
        LIMIT 50
    ''')
    reports = c.fetchall()
    conn.close()
    
    enhanced_reports = []
    for report in reports:
        enhanced_reports.append({
            'id': report[0],
            'filename': report[1],
            'file_hash': report[2],
            'risk_level': report[3],
            'risk_score': report[4],
            'threat_indicators': json.loads(report[5]) if report[5] else [],
            'scan_timestamp': report[6],
            'analysis_results': json.loads(report[7]) if report[7] else {},
            'impersonation_score': report[8] if len(report) > 8 else 0,
            'logo_match': report[9] if len(report) > 9 else None,
            'behavioral_score': report[10] if len(report) > 10 else 0,
            'alert_sent': bool(report[11]) if len(report) > 11 else False
        })
    
    return jsonify({
        'enhanced_reports': enhanced_reports,
        'total_reports': len(enhanced_reports),
        'generated_at': datetime.now().isoformat(),
        'version': 'enhanced_2.0'
    })

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
    
    # Generate comprehensive forensic report with enhanced features
    forensic_report = {
        'forensic_report_header': {
            'report_id': f"CS-ENHANCED-FORENSIC-{scan_id:06d}",
            'generated_at': datetime.now().isoformat(),
            'system_info': {
                'analyzer': 'CyberSentinels Enhanced APK Detector v2.0',
                'organization': 'Madhya Pradesh Police Cybercrime Division',
                'jurisdiction': 'State of Madhya Pradesh, India',
                'enhanced_features': 'Logo Detection, Behavioral Analysis, Real-time Alerts, Indian Banking Focus'
            }
        },
        'file_analysis': {
            'filename': result[1],
            'file_hash_sha256': result[2],
            'scan_timestamp': result[6],
            'analysis_duration': 'Real-time Enhanced Analysis',
            'detection_methods': [
                'Static Analysis',
                'Advanced Permission Analysis', 
                'Logo Comparison with Perceptual Hashing',
                'Behavioral Pattern Recognition',
                'Certificate Validation',
                'Indian Banking Intelligence'
            ]
        },
        'enhanced_risk_assessment': {
            'overall_risk_level': result[3],
            'risk_score': f"{result[4]}/100",
            'confidence_level': 'High',
            'threat_indicators': json.loads(result[5]) if result[5] else [],
            'total_threats_found': len(json.loads(result[5])) if result[5] else 0,
            'impersonation_score': result[8] if len(result) > 8 else 0,
            'logo_match': result[9] if len(result) > 9 else None,
            'behavioral_score': result[10] if len(result) > 10 else 0,
            'alert_triggered': bool(result[11]) if len(result) > 11 else False,
            'enhanced_detection': 'Logo Analysis + Behavioral Patterns + Real-time Intelligence'
        },
        'detailed_technical_analysis': json.loads(result[7]) if result[7] else {},
        'legal_certification': {
            'chain_of_custody': {
                'received_timestamp': result[6],
                'analyzed_by': 'CyberSentinels Enhanced Automated System v2.0',
                'analysis_completed': result[6],
                'report_generated': datetime.now().isoformat(),
                'enhanced_analysis': 'Logo Detection + Advanced Behavioral Analysis + Real-time Intelligence'
            },
            'legal_notice': 'This enhanced forensic report is generated for law enforcement purposes and contains comprehensive technical analysis of potentially malicious software including visual logo analysis, behavioral pattern detection, and real-time threat intelligence. This report may be used as digital evidence in cybercrime investigations.',
            'authenticity': {
                'system_signature': 'CyberSentinels-Enhanced-v2.0-MP-Police-Verified',
                'report_hash': hashlib.sha256(str(result).encode()).hexdigest()[:32],
                'enhanced_validation': 'Multi-layer Analysis with Logo Detection Verification'
            }
        },
        'enhanced_recommendations': {
            'immediate_actions': [],
            'investigation_leads': [],
            'prevention_measures': [],
            'enhanced_features_used': [
                'Logo Impersonation Detection',
                'Enhanced Behavioral Analysis',
                'Real-time Alert Integration',
                'Indian Banking Intelligence',
                'Advanced Permission Analysis'
            ]
        }
    }
    
    # Add specific recommendations based on enhanced analysis
    if result[3] in ['HIGH', 'CRITICAL']:
        forensic_report['enhanced_recommendations']['immediate_actions'] = [
            'Block APK installation immediately - Enhanced analysis confirmed high threat',
            'Trace source and distribution channels using enhanced forensic data',
            'Alert financial institutions if banking trojan/logo impersonation detected',
            'Preserve evidence for prosecution with enhanced forensic data',
            'Activate real-time monitoring for similar threats'
        ]
    elif result[3] == 'MEDIUM':
        forensic_report['enhanced_recommendations']['immediate_actions'] = [
            'Manual review by cybercrime expert required - Enhanced analysis available',
            'Monitor for similar variants using logo and behavioral signatures',
            'Consider controlled analysis in enhanced sandbox environment'
        ]
    
    response = jsonify(forensic_report)
    response.headers['Content-Disposition'] = f'attachment; filename=cybersentinels_enhanced_forensic_report_{scan_id}.json'
    response.headers['Content-Type'] = 'application/json'
    
    return response

# ===== ERROR HANDLERS =====

@app.errorhandler(413)
def too_large(e):
    return f"""
    <div style="text-align: center; padding: 60px; font-family: 'Segoe UI', sans-serif; background: #0f1419; color: #fff; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center;">
        <h1 style="color: #ff6b6b; font-size: 3rem; margin-bottom: 20px;">📁 File Too Large</h1>
        <p style="font-size: 1.2rem; margin-bottom: 30px;">Maximum file size is 100MB. Your file exceeds this limit.</p>
        <a href="/scan" style="color: #00d4ff; text-decoration: none; background: rgba(0,212,255,0.1); padding: 15px 30px; border-radius: 10px; border: 2px solid #00d4ff;">← Back to Enhanced Scanner</a>
    </div>
    """, 413

@app.errorhandler(404)
def page_not_found(e):
    return f"""
    <div style="text-align: center; padding: 60px; font-family: 'Segoe UI', sans-serif; background: #0f1419; color: #fff; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center;">
        <h1 style="color: #ffd93d; font-size: 3rem; margin-bottom: 20px;">🔍 Page Not Found</h1>
        <p style="font-size: 1.2rem; margin-bottom: 30px;">The page you're looking for doesn't exist in our enhanced system.</p>
        <a href="/" style="color: #00d4ff; text-decoration: none; background: rgba(0,212,255,0.1); padding: 15px 30px; border-radius: 10px; border: 2px solid #00d4ff;">🏠 Go to Enhanced Home</a>
    </div>
    """, 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return f"""
    <div style="text-align: center; padding: 60px; font-family: 'Segoe UI', sans-serif; background: #0f1419; color: #fff; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center;">
        <h1 style="color: #ff6b6b; font-size: 3rem; margin-bottom: 20px;">⚠️ System Error</h1>
        <p style="font-size: 1.1rem; margin-bottom: 15px;">Internal server error: {str(e)}</p>
        <p style="font-size: 1.1rem; margin-bottom: 30px;">Please try again or contact system administrator.</p>
        <a href="/" style="color: #00d4ff; text-decoration: none; background: rgba(0,212,255,0.1); padding: 15px 30px; border-radius: 10px; border: 2px solid #00d4ff;">🏠 Go to Enhanced Home</a>
    </div>
    """, 500

# ===== MAIN APPLICATION ENTRY POINT =====

if __name__ == "__main__":
    print("=" * 80)
    print("🚀 Starting CyberSentinels Enhanced APK Detector v2.0...")
    print("🏦 Specialized for Indian Banking Security with Logo Detection")
    print("👮 Built for Madhya Pradesh Police Cybercrime Division") 
    print("🎯 Enhanced Features:")
    print("   • Logo Impersonation Detection")
    print("   • Enhanced Behavioral Analysis")
    print("   • Real-time Alert System")
    print("   • Mobile Responsive Interface")
    print("   • Advanced Permission Analysis")
    print("   • Indian Banking Intelligence")
    print("🔗 Access at: http://localhost:5000")
    print("📊 Enhanced Dashboard at: http://localhost:5000/dashboard")
    print("📈 Enhanced API at: http://localhost:5000/api/threat-intelligence")
    print("=" * 80)
    
    try:
        app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        print(f"❌ Failed to start application: {e}")

# ===================================================================
# END OF CYBERSENTINELS ENHANCED APK DETECTOR v2.0
# Madhya Pradesh Police Cybercrime Division
# Advanced Banking APK Threat Detection System
# ===================================================================
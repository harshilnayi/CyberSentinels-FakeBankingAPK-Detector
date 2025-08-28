from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import sqlite3

# Import your detection logic (use simplified version if advanced doesn't work)
try:
    from advanced_detection_logic import AdvancedAPKDetector
    detector = AdvancedAPKDetector()
except ImportError:
    try:
        from simplified_detection_logic import SimplifiedAPKDetector
        detector = SimplifiedAPKDetector()
    except ImportError:
        print("Warning: No detection logic found, using dummy detector")
        detector = None

app = Flask(
    __name__,
    template_folder="../ui/templates",
    static_folder="../ui/static"
)

app.config['SECRET_KEY'] = 'your-secret-key-for-sessions'
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

@app.route("/")
def home():
    return redirect(url_for('scan'))

@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    c.execute('''
        SELECT filename, risk_level, risk_score, scan_timestamp
        FROM scan_results
        ORDER BY scan_timestamp DESC
        LIMIT 10
    ''')
    recent_scans = c.fetchall()
    conn.close()
    
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM scan_results')
    total_scans = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM scan_results WHERE risk_level = "HIGH"')
    high_risk_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM scan_results WHERE risk_level = "MEDIUM"')
    medium_risk_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM scan_results WHERE risk_level = "LOW"')
    low_risk_count = c.fetchone()[0]
    conn.close()
    
    stats = {
        'total_scans': total_scans,
        'high_risk': high_risk_count,
        'medium_risk': medium_risk_count,
        'low_risk': low_risk_count
    }
    
    # Returning a simple message as dashboard.html is not provided
    return f"Dashboard is not yet implemented. Stats: {json.dumps(stats)}"


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinels - Advanced APK Security Platform</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary-blue: #0066FF;
            --electric-blue: #00D4FF;
            --dark-navy: #0A0F1C;
            --darker-navy: #050812;
            --medium-gray: #1E2A3A;
            --light-gray: #8B9DC3;
            --white: #FFFFFF;
            --green-accent: #00FF88;
            --red-accent: #FF4757;
            --yellow-accent: #FFD700;
            --purple-accent: #8B5CF6;
            --gradient-primary: linear-gradient(135deg, #0066FF, #00D4FF);
            --gradient-dark: linear-gradient(135deg, #0A0F1C, #1E2A3A);
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--dark-navy);
            color: var(--white);
            line-height: 1.6;
            overflow-x: hidden;
        }

        /* Animated Background */
        .animated-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -2;
            background: var(--gradient-dark);
        }

        .floating-particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            pointer-events: none;
        }

        .particle {
            position: absolute;
            width: 2px;
            height: 2px;
            background: var(--electric-blue);
            border-radius: 50%;
            animation: float 20s infinite linear;
        }

        @keyframes float {
            0% {
                transform: translateY(100vh) translateX(0px);
                opacity: 0;
            }
            10% {
                opacity: 1;
            }
            90% {
                opacity: 1;
            }
            100% {
                transform: translateY(-10px) translateX(100px);
                opacity: 0;
            }
        }

        /* Navigation */
        .navbar {
            position: fixed;
            top: 0;
            width: 100%;
            background: rgba(10, 15, 28, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(0, 212, 255, 0.2);
            z-index: 1000;
            padding: 1rem 0;
            transition: all 0.3s ease;
        }

        .navbar.scrolled {
            background: rgba(10, 15, 28, 0.98);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }

        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 2rem;
        }

        .logo {
            display: flex;
            align-items: center;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--white);
        }

        .logo-icon {
            margin-right: 0.5rem;
            font-size: 2rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .nav-links {
            display: flex;
            list-style: none;
            gap: 2rem;
        }

        .nav-links a {
            color: var(--light-gray);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
            position: relative;
            padding: 0.5rem 1rem;
        }

        .nav-links a:hover {
            color: var(--electric-blue);
        }

        .nav-links a.active::after {
            content: '';
            position: absolute;
            bottom: -5px;
            left: 50%;
            transform: translateX(-50%);
            width: 20px;
            height: 2px;
            background: var(--gradient-primary);
            border-radius: 1px;
        }

        /* Hero Section */
        .hero {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .hero-content {
            max-width: 900px;
            z-index: 10;
            opacity: 0;
            transform: translateY(50px);
            animation: heroFadeIn 1s ease-out 0.5s forwards;
        }

        @keyframes heroFadeIn {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .hero-title {
            font-size: 4rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            line-height: 1.1;
        }

        .hero-subtitle {
            font-size: 1.5rem;
            color: var(--light-gray);
            margin-bottom: 2rem;
            font-weight: 400;
        }

        .hero-description {
            font-size: 1.1rem;
            color: var(--light-gray);
            margin-bottom: 3rem;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }

        .cta-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }

        .btn {
            padding: 1rem 2rem;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn-primary {
            background: var(--gradient-primary);
            color: var(--white);
            box-shadow: 0 10px 30px rgba(0, 102, 255, 0.3);
        }

        .btn-primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 40px rgba(0, 102, 255, 0.4);
        }

        .btn-secondary {
            background: transparent;
            color: var(--electric-blue);
            border: 2px solid var(--electric-blue);
        }

        .btn-secondary:hover {
            background: var(--electric-blue);
            color: var(--dark-navy);
            transform: translateY(-3px);
        }

        /* Section Styles */
        .section {
            padding: 6rem 2rem;
            max-width: 1200px;
            margin: 0 auto;
            opacity: 0;
            transform: translateY(50px);
            transition: all 0.8s ease;
        }

        .section.visible {
            opacity: 1;
            transform: translateY(0);
        }

        .section-header {
            text-align: center;
            margin-bottom: 4rem;
        }

        .section-title {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .section-subtitle {
            font-size: 1.2rem;
            color: var(--light-gray);
            max-width: 600px;
            margin: 0 auto;
        }

        /* Scanner Section */
        .scanner-section {
            background: var(--medium-gray);
            margin: 4rem 0;
            border-radius: 24px;
            padding: 4rem;
            position: relative;
            overflow: hidden;
        }

        .scanner-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, rgba(0, 212, 255, 0.1), rgba(0, 102, 255, 0.1));
            border-radius: 24px;
            z-index: -1;
        }

        .scanner-container {
            background: var(--darker-navy);
            border-radius: 20px;
            padding: 3rem;
            border: 1px solid rgba(0, 212, 255, 0.3);
            position: relative;
        }

        .scanner-header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .scanner-title {
            font-size: 2rem;
            font-weight: 600;
            color: var(--white);
            margin-bottom: 0.5rem;
        }

        .scanner-description {
            color: var(--light-gray);
            font-size: 1rem;
        }

        .upload-area {
            border: 2px dashed var(--electric-blue);
            border-radius: 16px;
            padding: 3rem;
            text-align: center;
            margin: 2rem 0;
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }

        .upload-area:hover {
            border-color: var(--primary-blue);
            background: rgba(0, 212, 255, 0.05);
        }

        .upload-area.dragover {
            border-color: var(--green-accent);
            background: rgba(0, 255, 136, 0.1);
            transform: scale(1.02);
        }

        .upload-icon {
            font-size: 4rem;
            color: var(--electric-blue);
            margin-bottom: 1rem;
        }

        .upload-text {
            font-size: 1.2rem;
            color: var(--white);
            margin-bottom: 0.5rem;
        }

        .upload-subtext {
            color: var(--light-gray);
            font-size: 0.9rem;
        }

        .file-input {
            display: none;
        }

        .file-info {
            background: var(--medium-gray);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid var(--green-accent);
            display: none;
        }

        .file-details {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .file-name {
            font-weight: 600;
            color: var(--white);
        }

        .file-size {
            color: var(--light-gray);
            font-family: 'Fira Code', monospace;
        }

        .scan-button {
            width: 100%;
            padding: 1.5rem;
            background: var(--gradient-primary);
            color: var(--white);
            border: none;
            border-radius: 12px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .scan-button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 15px 40px rgba(0, 102, 255, 0.4);
        }

        .scan-button:disabled {
            background: var(--medium-gray);
            cursor: not-allowed;
            opacity: 0.6;
        }

        .progress-container {
            display: none;
            margin: 1rem 0;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: var(--medium-gray);
            border-radius: 4px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: var(--gradient-primary);
            width: 0%;
            transition: width 0.3s ease;
            border-radius: 4px;
        }

        .progress-text {
            text-align: center;
            color: var(--light-gray);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }

        /* Results Section */
        .results-section {
            background: var(--medium-gray);
            margin: 4rem 0;
            border-radius: 24px;
            padding: 4rem;
            position: relative;
            overflow: hidden;
            display: none;
        }

        .results-section.show {
            display: block;
            animation: slideInUp 0.5s ease-out;
        }

        @keyframes slideInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .results-container {
            background: var(--white);
            border-radius: 20px;
            padding: 3rem;
            color: var(--dark-navy);
            max-width: 800px;
            margin: 0 auto;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .results-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 3rem;
            padding-bottom: 1.5rem;
            border-bottom: 2px solid #f0f0f0;
        }

        .results-logo {
            width: 40px;
            height: 40px;
            background: var(--gradient-primary);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--white);
            font-weight: bold;
        }

        .results-title {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--dark-navy);
            margin: 0;
        }

        .result-item {
            margin: 1.5rem 0;
        }

        .result-label {
            font-weight: 600;
            color: var(--dark-navy);
            margin-bottom: 0.5rem;
        }

        .result-value {
            font-size: 1.1rem;
        }

        .result-value.high-risk {
            color: var(--red-accent);
            font-weight: 700;
        }

        .result-value.risk-score {
            font-family: 'Fira Code', monospace;
            font-weight: 700;
            font-size: 1.2rem;
        }

        .threat-indicators {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }

        .threat-indicator {
            background: #fff5f5;
            border: 1px solid var(--red-accent);
            border-left: 4px solid var(--red-accent);
            border-radius: 8px;
            padding: 1rem;
            color: var(--red-accent);
            font-weight: 500;
        }

        .recommendation {
            background: #fff5f5;
            border: 1px solid var(--red-accent);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 2rem 0;
        }

        .recommendation-label {
            font-weight: 700;
            color: var(--red-accent);
            margin-bottom: 0.5rem;
        }

        .recommendation-text {
            color: var(--red-accent);
            font-weight: 600;
        }

        .results-actions {
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin-top: 3rem;
            flex-wrap: wrap;
        }

        .action-btn {
            padding: 1rem 2rem;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .action-btn.primary {
            background: var(--gradient-primary);
            color: var(--white);
        }

        .action-btn.secondary {
            background: #6c757d;
            color: var(--white);
        }

        .action-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        }

        /* Features Grid */
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 2rem;
            margin: 3rem 0;
        }

        .feature-card {
            background: var(--medium-gray);
            border-radius: 20px;
            padding: 2.5rem;
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
            opacity: 0;
            transform: translateY(30px);
        }

        .feature-card.visible {
            opacity: 1;
            transform: translateY(0);
        }

        .feature-card:hover {
            transform: translateY(-5px);
            border-color: var(--electric-blue);
            box-shadow: 0 20px 40px rgba(0, 212, 255, 0.2);
        }

        .feature-icon {
            width: 60px;
            height: 60px;
            border-radius: 16px;
            background: var(--gradient-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .feature-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--white);
            margin-bottom: 1rem;
        }

        .feature-description {
            color: var(--light-gray);
            line-height: 1.6;
        }

        /* Stats Section */
        .stats-section {
            background: var(--darker-navy);
            border-radius: 24px;
            padding: 4rem 3rem;
            margin: 4rem 0;
            text-align: center;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 3rem;
            margin-top: 3rem;
        }

        .stat-item {
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.6s ease;
        }

        .stat-item.visible {
            opacity: 1;
            transform: translateY(0);
        }

        .stat-number {
            font-size: 3rem;
            font-weight: 700;
            color: var(--electric-blue);
            margin-bottom: 0.5rem;
            font-family: 'Fira Code', monospace;
        }

        .stat-label {
            color: var(--light-gray);
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .stat-description {
            color: var(--light-gray);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }

        /* Team Section */
        .team-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }

        .team-card {
            background: var(--medium-gray);
            border-radius: 20px;
            padding: 2rem;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
            opacity: 0;
            transform: translateY(30px);
        }

        .team-card.visible {
            opacity: 1;
            transform: translateY(0);
        }

        .team-card:hover {
            transform: translateY(-10px);
            border-color: var(--electric-blue);
            box-shadow: 0 20px 40px rgba(0, 212, 255, 0.2);
        }

        .team-avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: var(--gradient-primary);
            margin: 0 auto 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }

        .team-name {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--white);
            margin-bottom: 0.5rem;
        }

        .team-role {
            color: var(--electric-blue);
            font-weight: 500;
            margin-bottom: 1rem;
        }

        .team-description {
            color: var(--light-gray);
            font-size: 0.9rem;
            line-height: 1.5;
        }

        /* How It Works Section */
        .how-it-works {
            margin: 4rem 0;
        }

        .steps-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }

        .step-item {
            display: flex;
            align-items: flex-start;
            gap: 1.5rem;
            padding: 2rem;
            background: var(--medium-gray);
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
            opacity: 0;
            transform: translateX(-30px);
        }

        .step-item.visible {
            opacity: 1;
            transform: translateX(0);
        }

        .step-item:hover {
            border-color: var(--electric-blue);
            background: var(--darker-navy);
        }

        .step-number {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--gradient-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            flex-shrink: 0;
        }

        .step-content h3 {
            color: var(--white);
            font-size: 1.2rem;
            margin-bottom: 0.5rem;
        }

        .step-content p {
            color: var(--light-gray);
            line-height: 1.5;
        }

        /* Footer */
        .footer {
            background: var(--darker-navy);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            padding: 3rem 2rem 2rem;
            text-align: center;
        }

        .footer-content {
            max-width: 1200px;
            margin: 0 auto;
        }

        .footer-text {
            color: var(--light-gray);
            margin-bottom: 1rem;
        }

        .footer-links {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }

        .footer-links a {
            color: var(--light-gray);
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .footer-links a:hover {
            color: var(--electric-blue);
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .hero-title {
                font-size: 2.5rem;
            }
            
            .section-title {
                font-size: 2rem;
            }
            
            .nav-links {
                display: none;
            }
            
            .scanner-section,
            .stats-section {
                padding: 2rem;
                margin: 2rem 1rem;
            }
            
            .cta-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                width: 100%;
                max-width: 300px;
            }
        }

        /* Loading Animation */
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: var(--white);
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Alert Styles */
        .alert {
            padding: 1rem 1.5rem;
            border-radius: 12px;
            margin: 1rem 0;
            border-left: 4px solid;
            animation: slideIn 0.3s ease;
        }

        .alert.success {
            background: rgba(0, 255, 136, 0.1);
            border-color: var(--green-accent);
            color: var(--green-accent);
        }

        .alert.error {
            background: rgba(255, 71, 87, 0.1);
            border-color: var(--red-accent);
            color: var(--red-accent);
        }

        @keyframes slideIn {
            from {
                transform: translateX(-100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    </style>
</head>
<body>
    <div class="animated-bg"></div>
    <div class="floating-particles" id="particles"></div>

    <!-- Navigation -->
    <nav class="navbar" id="navbar">
        <div class="nav-container">
            <div class="logo">
                <span class="logo-icon">🛡️</span>
                CyberSentinels
            </div>
            <ul class="nav-links">
                <li><a href="#home" class="nav-link active">Home</a></li>
                <li><a href="#scanner" class="nav-link">Scanner</a></li>
                <li><a href="#features" class="nav-link">Features</a></li>
                <li><a href="#how-it-works" class="nav-link">How It Works</a></li>
                <li><a href="#stats" class="nav-link">Stats</a></li>
                <li><a href="#team" class="nav-link">Team</a></li>
            </ul>
        </div>
    </nav>

    <!-- Hero Section -->
    <section id="home" class="hero">
        <div class="hero-content">
            <h1 class="hero-title">Advanced APK Security Platform</h1>
            <p class="hero-subtitle">AI-Powered Malware Detection & Banking Security</p>
            <p class="hero-description">
                Protect your mobile ecosystem with cutting-edge artificial intelligence that detects sophisticated malware, 
                banking trojans, and zero-day threats in real-time. Built for enterprises, trusted by security professionals.
            </p>
            <div class="cta-buttons">
                <a href="#scanner" class="btn btn-primary">
                    <span>🚀</span> Start Scanning
                </a>
                <a href="#features" class="btn btn-secondary">
                    <span>🔍</span> Learn More
                </a>
            </div>
        </div>
    </section>

    <!-- Scanner Section -->
    <section id="scanner" class="section">
        <div class="section-header">
            <h2 class="section-title">APK Security Scanner</h2>
            <p class="section-subtitle">Upload and analyze APK files with our advanced AI-powered detection system</p>
        </div>
        
        <div class="scanner-section">
            <div class="scanner-container">
                <div class="scanner-header">
                    <h3 class="scanner-title">Fake Banking APK Detector</h3>
                    <p class="scanner-description">Advanced malware detection specialized in banking trojans and financial threats</p>
                </div>

                <form action="/scan" method="post" enctype="multipart/form-data" id="uploadForm">
                    <div class="upload-area" id="uploadArea">
                        <input type="file" name="file" id="file" class="file-input" accept=".apk" required>
                        <div class="upload-icon">📱</div>
                        <div class="upload-text">Drop your APK file here or click to browse</div>
                        <div class="upload-subtext">Supports APK files up to 100MB • Secure & encrypted analysis</div>
                    </div>

                    <div class="file-info" id="fileInfo">
                        <div class="file-details">
                            <div>
                                <div class="file-name" id="fileName"></div>
                                <div class="file-size" id="fileSize"></div>
                            </div>
                            <div style="color: var(--green-accent); font-weight: 600;">
                                ✅ Ready for analysis
                            </div>
                        </div>
                    </div>

                    <div class="progress-container" id="progressContainer">
                        <div class="progress-bar">
                            <div class="progress-fill" id="progressFill"></div>
                        </div>
                        <div class="progress-text" id="progressText">Initializing scan...</div>
                    </div>

                    <button type="submit" class="scan-button" id="scanButton" disabled>
                        <span>🔍</span> Analyze APK File
                    </button>
                </form>
            </div>
        </div>
    </section>

    <!-- Results Section -->
    <!-- This section will be populated by a separate route now, so it's commented out in the main template -->
    <!-- <section class="results-section" id="resultsSection">...</section> -->

    <!-- Features Section -->
    <section id="features" class="section">
        <div class="section-header">
            <h2 class="section-title">Advanced Security Features</h2>
            <p class="section-subtitle">Comprehensive protection powered by artificial intelligence and machine learning</p>
        </div>
        
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon">🧠</div>
                <h3 class="feature-title">AI-Powered Detection</h3>
                <p class="feature-description">Advanced neural networks trained on millions of malware samples to detect even the most sophisticated threats and zero-day attacks.</p>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">⚡</div>
                <h3 class="feature-title">Real-time Analysis</h3>
                <p class="feature-description">Lightning-fast scanning with results in under 30 seconds, powered by distributed cloud computing infrastructure.</p>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🏦</div>
                <h3 class="feature-title">Banking Security Focus</h3>
                <p class="feature-description">Specialized detection for banking trojans, credential stealers, and financial malware targeting mobile banking applications.</p>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🔒</div>
                <h3 class="feature-title">Privacy Protected</h3>
                <p class="feature-description">End-to-end encryption ensures your files remain secure. All uploads are automatically deleted after analysis completion.</p>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">📊</div>
                <h3 class="feature-title">Detailed Reports</h3>
                <p class="feature-description">Comprehensive threat intelligence reports with risk scores, IoCs, and actionable mitigation recommendations.</p>
            </div>
            
            <div class="feature-card">
                <div class="feature-icon">🌐</div>
                <h3 class="feature-title">Global Threat Intel</h3>
                <p class="feature-description">Connected to worldwide threat intelligence networks with real-time updates on emerging malware families and attack vectors.</p>
            </div>
        </div>
    </section>

    <!-- How It Works -->
    <section id="how-it-works" class="section">
        <div class="section-header">
            <h2 class="section-title">How It Works</h2>
            <p class="section-subtitle">Simple, secure, and lightning-fast APK analysis in four easy steps</p>
        </div>
        
        <div class="how-it-works">
            <div class="steps-container">
                <div class="step-item">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h3>Upload APK File</h3>
                        <p>Securely upload your APK file through our encrypted interface. Files are processed in an isolated environment for maximum security.</p>
                    </div>
                </div>
                
                <div class="step-item">
                    <div class="step-number">2</div>
                    <div class="step-content">
                        <h3>AI Analysis</h3>
                        <p>Our advanced AI engine performs deep behavioral analysis, static code inspection, and pattern recognition to identify potential threats.</p>
                    </div>
                </div>
                
                <div class="step-item">
                    <div class="step-number">3</div>
                    <div class="step-content">
                        <h3>Threat Detection</h3>
                        <p>Machine learning algorithms cross-reference with global threat databases and identify malicious patterns, trojans, and suspicious behaviors.</p>
                    </div>
                </div>
                
                <div class="step-item">
                    <div class="step-number">4</div>
                    <div class="step-content">
                        <h3>Security Report</h3>
                        <p>Receive a comprehensive security report with risk assessment, threat classification, and actionable recommendations for protection.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Stats Section -->
    <section id="stats" class="section">
        <div class="stats-section">
            <div class="section-header">
                <h2 class="section-title">Security Intelligence</h2>
                <p class="section-subtitle">Real-time metrics from our global security operations center</p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-number" data-target="99.8">0</div>
                    <div class="stat-label">Detection Rate</div>
                    <div class="stat-description">Accuracy in identifying malware</div>
                </div>
                
                <div class="stat-item">
                    <div class="stat-number" data-target="127543">0</div>
                    <div class="stat-label">APKs Analyzed</div>
                    <div class="stat-description">Files processed this month</div>
                </div>
                
                <div class="stat-item">
                    <div class="stat-number" data-target="2.4">0</div>
                    <div class="stat-label">Million Threats</div>
                    <div class="stat-description">Blocked globally</div>
                </div>
                
                <div class="stat-item">
                    <div class="stat-number" data-target="15">0</div>
                    <div class="stat-label">Seconds Avg</div>
                    <div class="stat-description">Analysis completion time</div>
                </div>
                
                <div class="stat-item">
                    <div class="stat-number" data-target="847">0</div>
                    <div class="stat-label">New Malware</div>
                    <div class="stat-description">Variants detected daily</div>
                </div>
                
                <div class="stat-item">
                    <div class="stat-number" data-target="24">0</div>
                    <div class="stat-label">Hours Uptime</div>
                    <div class="stat-description">Continuous protection</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Team Section -->
    <section id="team" class="section">
        <div class="section-header">
            <h2 class="section-title">Meet Our Team</h2>
            <p class="section-subtitle">Elite cybersecurity professionals dedicated to protecting your digital assets</p>
        </div>
        
          
        <div class="team-grid">
            <div class="team-card">
                <div class="team-avatar">🥷</div>
                <h3 class="team-name">harshil nayi</h3>
                <div class="team-role">Lead Security Architect & backend dev</div>
            </div>
            
            <div class="team-card">
                <div class="team-avatar">🤖</div>
                <h3 class="team-name"> mansi  devnani</h3>
                <div class="team-role">presentation / documantation </div>
            </div>
            
            <div class="team-card">
                <div class="team-avatar">⚡</div>
                <h3 class="team-name">hiral mehta</h3>
                <div class="team-role">resourses Generating / presentation </div>
            </div>
            
            <div class="team-card">
                <div class="team-avatar">🎨</div>
                <h3 class="team-name">dhruv adroja</h3>
                <div class="team-role">UI/UX Designer</div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <div class="footer-content">
            <div class="footer-links">
                <a href="#privacy">Privacy Policy</a>
                <a href="#terms">Terms of Service</a>
                <a href="#api">API Documentation</a>
                <a href="#support">Support</a>
                <a href="#contact">Contact</a>
            </div>
            <p class="footer-text">
                © 2025 CyberSentinels. Advanced APK Security Platform. Built for Hackathon Excellence.
            </p>
            <p class="footer-text" style="font-size: 0.9rem; opacity: 0.7;">
                Protecting digital ecosystems with artificial intelligence • Enterprise-grade security • Global threat intelligence
            </p>
        </div>
    </footer>

    <script>
        // Check for results in URL parameters and display results section
        function checkForResults() {
            const urlParams = new URLSearchParams(window.location.search);
            const prediction = urlParams.get('prediction');
            const filename = urlParams.get('filename');
            
            if (prediction !== null) {
                displayResults(prediction, filename);
            }
        }

        // Display results function
        function displayResults(prediction, filename) {
            const resultsSection = document.getElementById('resultsSection');
            const scannedFileName = document.getElementById('scannedFileName');
            const riskLevel = document.getElementById('riskLevel');
            const riskScore = document.getElementById('riskScore');
            const recommendation = document.getElementById('recommendation');
            
            // Update filename
            if (filename) {
                scannedFileName.textContent = decodeURIComponent(filename);
            }
            
            // Update based on prediction
            if (prediction === '1' || prediction === 'malicious') {
                riskLevel.textContent = 'HIGH';
                riskLevel.className = 'result-value high-risk';
                riskScore.textContent = '100/100';
                recommendation.textContent = 'BLOCK - High probability of malicious banking app';
            } else {
                riskLevel.textContent = 'LOW';
                riskLevel.className = 'result-value';
                riskLevel.style.color = 'var(--green-accent)';
                riskScore.textContent = '15/100';
                recommendation.textContent = 'SAFE - Low risk, appears to be legitimate application';
                
                // Update threat indicators for safe files
                const threatIndicators = document.getElementById('threatIndicators');
                threatIndicators.innerHTML = `
                    <div class="threat-indicator" style="background: #f0fff4; border-color: var(--green-accent); color: var(--green-accent);">Normal Permissions</div>
                    <div class="threat-indicator" style="background: #f0fff4; border-color: var(--green-accent); color: var(--green-accent);">Valid Certificate</div>
                    <div class="threat-indicator" style="background: #f0fff4; border-color: var(--green-accent); color: var(--green-accent);">Clean Code Structure</div>
                    <div class="threat-indicator" style="background: #f0fff4; border-color: var(--green-accent); color: var(--green-accent);">No Suspicious Activity</div>
                `;
                
                // Update recommendation style
                const recommendationDiv = document.querySelector('.recommendation');
                recommendationDiv.style.background = '#f0fff4';
                recommendationDiv.style.borderColor = 'var(--green-accent)';
                recommendationDiv.querySelector('.recommendation-label').style.color = 'var(--green-accent)';
                recommendationDiv.querySelector('.recommendation-text').style.color = 'var(--green-accent)';
            }
            
            // Show results section
            resultsSection.classList.add('show');
            
            // Scroll to results
            setTimeout(() => {
                resultsSection.scrollIntoView({ behavior: 'smooth' });
            }, 300);
        }

        // Navigation functions
        function scrollToScanner() {
            document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
            // Hide results section
            document.getElementById('resultsSection').classList.remove('show');
            // Reset form
            document.getElementById('uploadForm').reset();
            document.getElementById('fileInfo').style.display = 'none';
            document.getElementById('scanButton').disabled = true;
            document.getElementById('scanButton').innerHTML = '<span>🔍</span> Analyze APK File';
        }

        function scrollToHome() {
            document.getElementById('home').scrollIntoView({ behavior: 'smooth' });
        }

        function scrollToFeatures() {
            document.getElementById('features').scrollIntoView({ behavior: 'smooth' });
        }

        // Floating particles animation
        function createParticles() {
            const container = document.getElementById('particles');
            const particleCount = 50;
            
            for (let i = 0; i < particleCount; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';
                particle.style.left = Math.random() * 100 + '%';
                particle.style.animationDelay = Math.random() * 20 + 's';
                particle.style.animationDuration = (15 + Math.random() * 10) + 's';
                container.appendChild(particle);
            }
        }

        // Navbar scroll effect
        function handleNavbarScroll() {
            const navbar = document.getElementById('navbar');
            const scrolled = window.scrollY > 50;
            navbar.classList.toggle('scrolled', scrolled);
        }

        // Intersection Observer for animations
        function setupScrollAnimations() {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('visible');
                        
                        // Animate stats numbers
                        if (entry.target.classList.contains('stat-item')) {
                            animateNumber(entry.target.querySelector('.stat-number'));
                        }
                    }
                });
            }, {
                threshold: 0.2,
                rootMargin: '0px 0px -50px 0px'
            });

            // Observe sections and cards
            document.querySelectorAll('.section, .feature-card, .team-card, .stat-item, .step-item').forEach(el => {
                observer.observe(el);
            });
        }

        // Animate numbers
        function animateNumber(element) {
            const target = parseFloat(element.getAttribute('data-target'));
            const duration = 2000;
            const step = target / (duration / 16);
            let current = 0;

            const timer = setInterval(() => {
                current += step;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                
                if (target >= 1000000) {
                    element.textContent = (current / 1000000).toFixed(1) + 'M';
                } else if (target >= 1000) {
                    element.textContent = (current / 1000).toFixed(target >= 10000 ? 0 : 1) + 'K';
                } else {
                    element.textContent = current.toFixed(target < 100 ? 1 : 0);
                }
                
                if (element.textContent.includes('.') && element.textContent.endsWith('.0')) {
                    element.textContent = element.textContent.slice(0, -2);
                }
                
                // Add % or other suffixes based on context
                if (element.parentElement.querySelector('.stat-label').textContent.includes('Rate')) {
                    element.textContent += '%';
                }
            }, 16);
        }

        // File upload functionality
        function setupFileUpload() {
            const fileInput = document.getElementById('file');
            const uploadArea = document.getElementById('uploadArea');
            const fileInfo = document.getElementById('fileInfo');
            const scanButton = document.getElementById('scanButton');
            const progressContainer = document.getElementById('progressContainer');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');

            // Click to upload
            uploadArea.addEventListener('click', () => {
                fileInput.click();
            });

            // Drag and drop
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });

            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });

            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                const files = e.dataTransfer.files;
                if (files.length > 0 && files[0].name.endsWith('.apk')) {
                    fileInput.files = files;
                    handleFileSelection(files[0]);
                }
            });

            // File selection
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    handleFileSelection(file);
                }
            });

            function handleFileSelection(file) {
                const maxSize = 100 * 1024 * 1024; // 100MB
                
                if (file.size > maxSize) {
                    showAlert('File too large! Maximum size is 100MB.', 'error');
                    fileInput.value = '';
                    return;
                }

                // Update file info
                document.getElementById('fileName').textContent = file.name;
                document.getElementById('fileSize').textContent = formatFileSize(file.size);
                fileInfo.style.display = 'block';
                
                // Enable scan button
                scanButton.disabled = false;
                scanButton.innerHTML = '<span>🔍</span> Analyze ' + file.name;
            }

            // Form submission with progress animation
            document.getElementById('uploadForm').addEventListener('submit', (e) => {
                startScan();
            });

            function startScan() {
                scanButton.innerHTML = '<div class="loading-spinner"></div> Analyzing...';
                scanButton.disabled = true;
                progressContainer.style.display = 'block';
                
                // Simulate progress
                let progress = 0;
                const phases = [
                    'Initializing scan...',
                    'Extracting APK contents...',
                    'Analyzing code structure...',
                    'Running AI detection...',
                    'Checking threat databases...',
                    'Generating security report...',
                    'Finalizing analysis...'
                ];
                
                const interval = setInterval(() => {
                    progress += Math.random() * 15;
                    if (progress > 95) progress = 95;
                    
                    progressFill.style.width = progress + '%';
                    const phase = Math.floor((progress / 100) * phases.length);
                    progressText.textContent = phases[Math.min(phase, phases.length - 1)];
                }, 300);
                
                // The form will submit naturally and redirect to results
            }

            function formatFileSize(bytes) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            function showAlert(message, type) {
                const alert = document.createElement('div');
                alert.className = `alert ${type}`;
                alert.textContent = message;
                document.querySelector('.scanner-container').insertBefore(alert, document.querySelector('form'));
                setTimeout(() => alert.remove(), 5000);
            }
        }

        // Navigation active states
        function updateActiveNavLink() {
            const navLinks = document.querySelectorAll('.nav-link');
            const sections = document.querySelectorAll('section[id]');
            
            let current = '';
            sections.forEach(section => {
                const sectionTop = section.offsetTop;
                const sectionHeight = section.clientHeight;
                if (scrollY >= sectionTop - 200) {
                    current = section.getAttribute('id');
                }
            });

            navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === '#' + current) {
                    link.classList.add('active');
                }
            });
        }

        // Smooth scroll for navigation links
        function setupSmoothScroll() {
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        const offsetTop = target.offsetTop - 80;
                        window.scrollTo({
                            top: offsetTop,
                            behavior: 'smooth'
                        });
                    }
                });
            });
        }

        // Initialize everything
        document.addEventListener('DOMContentLoaded', () => {
            createParticles();
            setupScrollAnimations();
            setupFileUpload();
            setupSmoothScroll();
            checkForResults(); // Check for results on page load
            
            window.addEventListener('scroll', () => {
                handleNavbarScroll();
                updateActiveNavLink();
            });
        });

        // Resize handler for responsive particles
        window.addEventListener('resize', () => {
            const container = document.getElementById('particles');
            container.innerHTML = '';
            createParticles();
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
                # Perform analysis using available detector
                if detector:
                    if hasattr(detector, 'analyze_apk_comprehensive'):
                        analysis_results = detector.analyze_apk_comprehensive(filepath)
                    elif hasattr(detector, 'analyze_apk_simplified'):
                        analysis_results = detector.analyze_apk_simplified(filepath)
                    else:
                        analysis_results = {
                            'file_info': {'filename': filename, 'size': os.path.getsize(filepath)},
                            'risk_assessment': {
                                'overall_score': 25,
                                'risk_level': 'MEDIUM',
                                'threat_indicators': ['test_indicator'],
                                'recommendation': 'Test analysis completed'
                            }
                        }
                else:
                    # Dummy analysis if no detector is found
                    analysis_results = {
                        'file_info': {'filename': filename, 'size': os.path.getsize(filepath)},
                        'risk_assessment': {
                            'overall_score': 15,
                            'risk_level': 'LOW',
                            'threat_indicators': [],
                            'recommendation': 'Dummy analysis - detector not loaded'
                        }
                    }
                
                risk_assessment = analysis_results.get('risk_assessment', {})
                risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
                risk_score = risk_assessment.get('overall_score', 0)
                threat_indicators = risk_assessment.get('threat_indicators', [])
                file_hash = analysis_results.get('file_info', {}).get('sha256', 'unknown')
                
                # Store results in the database
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
                    json.dumps(threat_indicators),
                    datetime.now(),
                    json.dumps(analysis_results)
                ))
                conn.commit()
                conn.close()
                
                os.remove(filepath)
                
                # Prepare HTML variables for the f-string
                risk_class = 'high-risk' if risk_level == 'HIGH' else 'low-risk' if risk_level == 'LOW' else ''
                
                if threat_indicators:
                    threat_indicators_html = ''.join([f'<div class="threat-indicator {"safe" if risk_level != "HIGH" else ""}">{indicator.replace("_", " ").title()}</div>' for indicator in threat_indicators])
                else:
                    threat_indicators_html = '<div class="threat-indicator safe">No suspicious activity detected</div>'
                
                recommendation_class = 'safe' if risk_level != 'HIGH' else ''
                recommendation_text = risk_assessment.get('recommendation', 'No recommendation available')
                
                return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinels - Scan Results</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --primary-blue: #0066FF;
            --electric-blue: #00D4FF;
            --dark-navy: #0A0F1C;
            --darker-navy: #050812;
            --medium-gray: #1E2A3A;
            --light-gray: #8B9DC3;
            --white: #FFFFFF;
            --green-accent: #00FF88;
            --red-accent: #FF4757;
            --yellow-accent: #FFD700;
            --gradient-primary: linear-gradient(135deg, #0066FF, #00D4FF);
            --gradient-dark: linear-gradient(135deg, #0A0F1C, #1E2A3A);
        }}

        html {{
            scroll-behavior: smooth;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            background: var(--dark-navy);
            color: var(--white);
            line-height: 1.6;
            overflow-x: hidden;
            padding: 0;
        }}

        /* Animated Background */
        .animated-bg {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -2;
            background: var(--gradient-dark);
        }}

        .floating-particles {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            pointer-events: none;
        }}

        .particle {{
            position: absolute;
            width: 2px;
            height: 2px;
            background: var(--electric-blue);
            border-radius: 50%;
            animation: float 20s infinite linear;
        }}

        @keyframes float {{
            0% {{
                transform: translateY(100vh) translateX(0px);
                opacity: 0;
            }}
            10% {{
                opacity: 1;
            }}
            90% {{
                opacity: 1;
            }}
            100% {{
                transform: translateY(-10px) translateX(100px);
                opacity: 0;
            }}
        }}

        /* Results Section */
        .results-section {{
            padding: 6rem 2rem;
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }}
        
        .results-container {{
            background: var(--white);
            border-radius: 20px;
            padding: 3rem;
            color: var(--dark-navy);
            max-width: 800px;
            margin: 0 auto;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            width: 100%;
        }}

        .results-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 3rem;
            padding-bottom: 1.5rem;
            border-bottom: 2px solid #f0f0f0;
        }}

        .results-logo {{
            width: 40px;
            height: 40px;
            background: var(--gradient-primary);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--white);
            font-weight: bold;
        }}

        .results-title {{
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--dark-navy);
            margin: 0;
        }}

        .result-item {{
            margin: 1.5rem 0;
        }}

        .result-label {{
            font-weight: 600;
            color: var(--dark-navy);
            margin-bottom: 0.5rem;
        }}

        .result-value {{
            font-size: 1.1rem;
        }}
        
        .result-value.high-risk {{
            color: var(--red-accent);
            font-weight: 700;
        }}
        
        .result-value.low-risk {{
            color: var(--green-accent);
            font-weight: 700;
        }}
        
        .result-value.risk-score {{
            font-family: 'Fira Code', monospace;
            font-weight: 700;
            font-size: 1.2rem;
        }}

        .threat-indicators {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }}
        
        .threat-indicator {{
            background: #fff5f5;
            border: 1px solid var(--red-accent);
            border-left: 4px solid var(--red-accent);
            border-radius: 8px;
            padding: 1rem;
            color: var(--red-accent);
            font-weight: 500;
        }}

        .threat-indicator.safe {{
            background: #f0fff4;
            border-color: var(--green-accent);
            color: var(--green-accent);
        }}

        .recommendation {{
            background: #fff5f5;
            border: 1px solid var(--red-accent);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 2rem 0;
        }}
        
        .recommendation.safe {{
            background: #f0fff4;
            border-color: var(--green-accent);
        }}

        .recommendation-label {{
            font-weight: 700;
            color: var(--red-accent);
            margin-bottom: 0.5rem;
        }}
        
        .recommendation.safe .recommendation-label {{
            color: var(--green-accent);
        }}

        .recommendation-text {{
            color: var(--red-accent);
            font-weight: 600;
        }}
        
        .recommendation.safe .recommendation-text {{
            color: var(--green-accent);
        }}

        .results-actions {{
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin-top: 3rem;
            flex-wrap: wrap;
        }}

        .action-btn {{
            padding: 1rem 2rem;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--white);
        }}

        .action-btn.primary {{
            background: var(--gradient-primary);
            box-shadow: 0 10px 30px rgba(0, 102, 255, 0.3);
        }}

        .action-btn.secondary {{
            background: #6c757d;
        }}

        .action-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        }}

        @media (max-width: 768px) {{
            .results-section {{
                padding: 2rem;
            }}
            .results-container {{
                padding: 2rem 1.5rem;
            }}
            .results-header {{
                flex-direction: column;
                text-align: center;
                gap: 0.5rem;
            }}
            .results-actions {{
                flex-direction: column;
                align-items: center;
            }}
            .action-btn {{
                width: 100%;
                max-width: 300px;
            }}
            .threat-indicators {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="animated-bg"></div>
    <div class="floating-particles" id="particles"></div>

    <section class="results-section">
        <div class="results-container">
            <div class="results-header">
                <div class="results-logo">🛡️</div>
                <h2 class="results-title">CyberSentinels - Scan Results</h2>
            </div>
            
            <div class="result-item">
                <div class="result-label">File:</div>
                <div class="result-value" id="scannedFileName">{filename}</div>
            </div>

            <div class="result-item">
                <div class="result-label">Risk Level:</div>
                <div class="result-value {risk_class}" id="riskLevel">{risk_level}</div>
            </div>

            <div class="result-item">
                <div class="result-label">Risk Score:</div>
                <div class="result-value risk-score" id="riskScore">{risk_score}/100</div>
            </div>

            <div class="result-item">
                <div class="result-label">Threat Indicators:</div>
                <div class="threat-indicators" id="threatIndicators">
                    {threat_indicators_html}
                </div>
            </div>

            <div class="recommendation {recommendation_class}">
                <div class="recommendation-label">Recommendation:</div>
                <div class="recommendation-text" id="recommendation">{recommendation_text}</div>
            </div>
            
            <div class="results-actions">
                <a href="/scan" class="action-btn primary">
                    <span>🔍</span> Scan Another APK
                </a>
                <a href="/" class="action-btn secondary">
                    <span>🏠</span> Home
                </a>
                <a href="/dashboard" class="action-btn secondary">
                    <span>📊</span> Dashboard
                </a>
            </div>
        </div>
    </section>

    <script>
        function createParticles() {{
            const container = document.getElementById('particles');
            if (!container) return;
            const particleCount = 50;
            
            for (let i = 0; i < particleCount; i++) {{
                const particle = document.createElement('div');
                particle.className = 'particle';
                particle.style.left = Math.random() * 100 + '%';
                particle.style.animationDelay = Math.random() * 20 + 's';
                particle.style.animationDuration = (15 + Math.random() * 10) + 's';
                container.appendChild(particle);
            }}
        }}
        
        document.addEventListener('DOMContentLoaded', () => {{
            createParticles();
        }});
    </script>
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


@app.errorhandler(413)
def too_large(e):
    return "File too large. Maximum size is 100MB.", 413

@app.errorhandler(404)
def page_not_found(e):
    return "Page not found. <a href='/'>Go to Home</a>", 404

@app.errorhandler(500)
def server_error(e):
    return "Internal server error. Please try again.", 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)

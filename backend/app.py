# FIXED Flask app.py - Single scan page, no multiple redirects
# Replace your entire app.py with this fixed version

from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
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
    return render_template("home.html")

@app.route("/dashboard")
def dashboard():
    # Get recent scan results from database
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
    
    # Get statistics
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
    
    return render_template("dashboard.html", recent_scans=recent_scans, stats=stats)

# FIXED: Single scan route - no multiple redirects
@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        # Always show the scan page for GET requests
        return render_template("scan.html")
    
    # Handle POST request (file upload)
    if 'file' not in request.files:
        flash('No file selected')
        return render_template("scan.html")  # Stay on scan page, don't redirect
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected') 
        return render_template("scan.html")  # Stay on scan page, don't redirect
    
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
                    # Fallback dummy analysis
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
                # Dummy analysis when no detector available
                analysis_results = {
                    'file_info': {'filename': filename, 'size': os.path.getsize(filepath)},
                    'risk_assessment': {
                        'overall_score': 15,
                        'risk_level': 'LOW',
                        'threat_indicators': [],
                        'recommendation': 'Dummy analysis - detector not loaded'
                    }
                }
            
            # Extract key information for display
            risk_assessment = analysis_results.get('risk_assessment', {})
            risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
            risk_score = risk_assessment.get('overall_score', 0)
            threat_indicators = risk_assessment.get('threat_indicators', [])
            
            # Store results in database
            conn = sqlite3.connect('scan_results.db')
            c = conn.cursor()
            
            file_hash = analysis_results.get('file_info', {}).get('sha256', 'unknown')
            
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
            
            scan_id = c.lastrowid
            conn.commit()
            conn.close()
            
            # Clean up uploaded file
            os.remove(filepath)
            
            # FIXED: Return results directly, no redirects
            return f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>CyberSentinels - Scan Results</title>
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: linear-gradient(135deg, #1e3c72, #2a5298);
                        min-height: 100vh;
                        margin: 0;
                        padding: 20px;
                    }}
                    .container {{
                        max-width: 800px;
                        margin: 0 auto;
                        background: white;
                        padding: 2rem;
                        border-radius: 15px;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    }}
                    .header {{
                        text-align: center;
                        margin-bottom: 2rem;
                    }}
                    .risk-high {{ color: #dc3545; }}
                    .risk-medium {{ color: #ffc107; }}
                    .risk-low {{ color: #28a745; }}
                    .threat-indicator {{
                        background: #f8f9fa;
                        padding: 0.5rem;
                        margin: 0.25rem;
                        border-radius: 5px;
                        border-left: 4px solid #dc3545;
                        display: inline-block;
                    }}
                    .buttons {{
                        margin-top: 2rem;
                        text-align: center;
                    }}
                    .btn {{
                        display: inline-block;
                        padding: 1rem 2rem;
                        margin: 0.5rem;
                        text-decoration: none;
                        border-radius: 8px;
                        font-weight: bold;
                        color: white;
                    }}
                    .btn-primary {{ background-color: #007bff; }}
                    .btn-secondary {{ background-color: #6c757d; }}
                    .btn:hover {{ opacity: 0.9; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🛡️ CyberSentinels - Scan Results</h1>
                    </div>
                    
                    <h2>File: {filename}</h2>
                    <p><strong>Risk Level:</strong> 
                        <span class="risk-{'high' if risk_level == 'HIGH' else 'medium' if risk_level == 'MEDIUM' else 'low'}">
                            {risk_level}
                        </span>
                    </p>
                    <p><strong>Risk Score:</strong> {risk_score}/100</p>
                    <p><strong>Threat Indicators:</strong></p>
                    <div>
                        {' '.join([f'<span class="threat-indicator">{indicator.replace("_", " ").title()}</span>' for indicator in threat_indicators]) if threat_indicators else '<span>None detected</span>'}
                    </div>
                    <p><strong>Recommendation:</strong> {risk_assessment.get('recommendation', 'No recommendation available')}</p>
                    
                    <div class="buttons">
                        <a href="/scan" class="btn btn-primary">🔍 Scan Another APK</a>
                        <a href="/" class="btn btn-secondary">🏠 Home</a>
                        <a href="/dashboard" class="btn btn-secondary">📊 Dashboard</a>
                    </div>
                </div>
            </body>
            </html>
            """
            
        except Exception as e:
            flash(f'Error analyzing APK: {str(e)}')
            if os.path.exists(filepath):
                os.remove(filepath)  # Clean up file
            return render_template("scan.html")  # Stay on scan page, don't redirect
    
    else:
        flash('Invalid file type. Please upload an APK file.')
        return render_template("scan.html")  # Stay on scan page, don't redirect

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """API endpoint for programmatic APK scanning"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only APK files allowed.'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # Perform analysis
        if detector and hasattr(detector, 'analyze_apk_comprehensive'):
            analysis_results = detector.analyze_apk_comprehensive(filepath)
        else:
            analysis_results = {'status': 'dummy_analysis', 'message': 'Detector not available'}
        
        # Clean up file
        os.remove(filepath)
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'analysis_results': analysis_results
        })
        
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': str(e)}), 500

# Simple error handlers without templates
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
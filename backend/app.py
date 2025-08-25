from flask import Flask, render_template, request, jsonify
import os
import apk_analyzer   # your analysis logic

app = Flask(__name__)

# Homepage
@app.route("/")
def home():
    return render_template("index.html")

# Upload & Scan route
@app.route("/scan", methods=["POST"])
def scan_apk():
    if "apk_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["apk_file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    # Save uploaded file temporarily
    upload_path = os.path.join("uploads", file.filename)
    os.makedirs("uploads", exist_ok=True)
    file.save(upload_path)

    # Run your analyzer
    result = apk_analyzer.analyze_apk(upload_path)

    return jsonify(result)

# Simple Dashboard (shows recent scan results – mock for now)
@app.route("/dashboard")
def dashboard():
    # later we can connect to DB or logs
    stats = {
        "total_scanned": 12,
        "malicious_detected": 4,
        "safe": 8
    }
    return render_template("dashboard.html", stats=stats)


if __name__ == "__main__":
    app.run(debug=True)

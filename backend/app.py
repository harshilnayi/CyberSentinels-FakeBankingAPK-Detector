# backend/app.py
from flask import Flask, render_template, request, redirect, url_for
import os
from scan_utils import scan_apk

app = Flask(__name__)

# Dummy stats (pretend these are being tracked)
dummy_stats = {
    "total_scans": 42,
    "fake_detected": 7,
    "safe_detected": 35,
    "latest_scans": [
        {"filename": "BankingApp_v1.apk", "result": "Fake"},
        {"filename": "MyWallet.apk", "result": "Safe"},
        {"filename": "SecureBank.apk", "result": "Safe"},
        {"filename": "XYZPay.apk", "result": "Fake"},
    ]
}

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/scan", methods=["POST"])
def scan():
    if "apk_file" not in request.files:
        return "No file uploaded", 400
    
    apk = request.files["apk_file"]
    if apk.filename == "":
        return "No selected file", 400
    
    filepath = os.path.join(UPLOAD_FOLDER, apk.filename)
    apk.save(filepath)

    # Fake scan logic (always returns random result for demo)
    result = scan_apk(filepath)

    return render_template("result.html", filename=apk.filename, result=result)

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", stats=dummy_stats)

if __name__ == "__main__":
    app.run(debug=True)

from flask import Flask, request, jsonify
from apk_analyzer import analyze_apk

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files['file']
    result = analyze_apk(file)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)

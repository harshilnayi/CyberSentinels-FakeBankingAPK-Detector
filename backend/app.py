from flask import Flask, render_template, request, redirect, url_for

app = Flask(
    __name__,
    template_folder="../ui/templates",
    static_folder="../ui/static"
)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# ✅ Dummy scan route
@app.route("/scan", methods=["POST"])
def scan():
    # just redirect to dashboard, no processing yet
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)

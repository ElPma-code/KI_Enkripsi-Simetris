from flask import Flask, render_template

app = Flask(__name__)

# Halaman utama
@app.route("/")
def home():
    return render_template("index.html")

# Halaman dashboard sementara
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)

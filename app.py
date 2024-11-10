from flask import Flask, render_template, request, jsonify
import re
import tldextract
from urllib.parse import urlparse

app = Flask(__name__)

# Suspicious keywords and TLDs
suspicious_keywords = [
    "login", "secure", "account", "update", "verify", "signin",
    "banking", "confirm", "password", "support", "alert", "free",
    "prize", "win", "click"
]
suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"]

def check_hyphens(url):
    return url.count('-') > 3

def is_ip_address(url):
    pattern = re.compile(r"^(http[s]?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/|$)")
    return pattern.match(url)

def contains_suspicious_keywords(url):
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return True
    return False

def has_suspicious_tld(url):
    ext = tldextract.extract(url)
    return '.' + ext.suffix in suspicious_tlds

def is_phishing_link(url):
    result = {
        "is_phishing": False,
        "message": "The link is safe.",
        "reasons": []
    }
    if check_hyphens(url):
        result["is_phishing"] = True
        result["reasons"].append("Too many hyphens in the URL.")
    if is_ip_address(url):
        result["is_phishing"] = True
        result["reasons"].append("Uses an IP address instead of a domain.")
    if contains_suspicious_keywords(url):
        result["is_phishing"] = True
        result["reasons"].append("Contains phishing-related keywords.")
    if has_suspicious_tld(url):
        result["is_phishing"] = True
        result["reasons"].append("Suspicious TLD detected.")

    if result["is_phishing"]:
        result["message"] = "Warning: The link is not safe!"
    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    url = request.form['url']
    result = is_phishing_link(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)

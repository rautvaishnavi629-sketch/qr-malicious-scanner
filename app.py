from flask import Flask, render_template, request, jsonify
import cv2
import numpy as np
from urllib.parse import urlparse

app = Flask(__name__)


def check_url(url):
    reasons = []
    factors = []
    score = 0

    url_lower = url.lower().strip()
    parsed = urlparse(url_lower)

    is_payment_qr = url_lower.startswith("upi://pay")

    if parsed.scheme == "http":
        score += 20
        factors.append("HTTP instead of HTTPS")
        reasons.append("Uses HTTP instead of HTTPS")

    elif parsed.scheme == "https":
        factors.append("HTTPS used")

    elif is_payment_qr:
        factors.append("UPI payment QR detected")

    elif parsed.scheme:
        score += 20
        factors.append("Unusual URL scheme")
        reasons.append("Uses an unusual URL scheme")

    else:
        return (
            "SAFE",
            0,
            ["QR contains text or content that is not a web URL."],
            ["Non-URL QR content"],
            False
        )

    suspicious_words = [
        "login",
        "verify",
        "account",
        "update",
        "password",
        "free"
    ]

    found_keyword = False

    for word in suspicious_words:
        if word in url_lower:
            score += 15
            factors.append("Suspicious keyword")
            reasons.append("Contains suspicious keyword: " + word)
            found_keyword = True
            break

    if not found_keyword:
        factors.append("No suspicious keyword")

    if "@" in url:
        score += 20
        factors.append("@ symbol detected")
        reasons.append("Contains @ symbol in the URL")
    else:
        factors.append("No @ symbol")

    if len(url) > 150:
        score += 15
        factors.append("Unusually long URL")
        reasons.append("URL is unusually long")
    else:
        factors.append("Normal URL length")

    hostname = parsed.hostname

    if hostname:
        parts = hostname.split(".")

        if len(parts) == 4 and all(part.isdigit() for part in parts):
            score += 15
            factors.append("IP address used")
            reasons.append("URL uses an IP address instead of a domain name")
        else:
            factors.append("Normal domain format")

        if "xn--" in hostname:
            score += 10
            factors.append("Unusual encoded domain")
            reasons.append("Domain contains an unusual encoded name")

        if len(parts) > 4:
            score += 10
            factors.append("Many subdomains")
            reasons.append(
                "Domain contains an unusually large number of subdomains"
            )
        else:
            factors.append("Normal number of subdomains")

    score = min(score, 100)

    if score >= 60:
        result = "MALICIOUS"
    elif score >= 30:
        result = "SUSPICIOUS"
    else:
        result = "SAFE"

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return result, score, reasons, factors, is_payment_qr


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    if "qr_image" not in request.files:
        return jsonify({
            "success": False,
            "error": "No QR image uploaded."
        }), 400

    file = request.files["qr_image"]

    if file.filename == "":
        return jsonify({
            "success": False,
            "error": "Please select a QR code image."
        }), 400

    try:
        image_bytes = file.read()

        image_array = np.frombuffer(image_bytes, np.uint8)

        image = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR
        )

        if image is None:
            return jsonify({
                "success": False,
                "error": "Unable to read the uploaded image."
            }), 400

        detector = cv2.QRCodeDetector()

        decoded_data, points, _ = detector.detectAndDecode(image)

        if not decoded_data:
            return jsonify({
                "success": False,
                "error": "No QR code detected. Please upload a clear QR image."
            }), 400

        result, score, reasons, factors, is_payment_qr = check_url(
            decoded_data
        )

        return jsonify({
            "success": True,
            "decoded_data": decoded_data,
            "result": result,
            "score": score,
            "reasons": reasons,
            "factors": factors,
            "is_payment_qr": is_payment_qr
        })

    except Exception:
        return jsonify({
            "success": False,
            "error": "An error occurred while scanning the QR code."
        }), 500


if __name__ == "__main__":
    app.run(debug=True)
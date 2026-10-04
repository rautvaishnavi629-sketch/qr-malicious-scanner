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

    # HTTPS / HTTP Check
    if parsed.scheme == "http":
        score += 20
        factors.append("HTTP instead of HTTPS")
        reasons.append("Uses HTTP instead of HTTPS")

    elif parsed.scheme == "https":
        factors.append("HTTPS used")

    elif parsed.scheme == "upi" and is_payment_qr:
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

    # Suspicious Keyword Check
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

    # @ Symbol Check
    if "@" in url:
        score += 20
        factors.append("@ symbol detected")
        reasons.append("Contains @ symbol in the URL")
    else:
        factors.append("No @ symbol")

    # URL Length Check
    if len(url) > 150:
        score += 15
        factors.append("Unusually long URL")
        reasons.append("URL is unusually long")
    else:
        factors.append("Normal URL length")

    # Domain Checks
    hostname = parsed.hostname

    if hostname:
        parts = hostname.split(".")

        # IP Address Check
        if len(parts) == 4 and all(
            part.isdigit() for part in parts
        ):
            score += 15
            factors.append("IP address used")
            reasons.append(
                "URL uses an IP address instead of a domain name"
            )
        else:
            factors.append("Normal domain format")

        # Punycode / Encoded Domain Check
        if "xn--" in hostname:
            score += 10
            factors.append("Unusual encoded domain")
            reasons.append(
                "Domain contains an unusual encoded name"
            )

        # Subdomain Check
        domain_parts = hostname.split(".")

        if len(domain_parts) > 4:
            score += 10
            factors.append("Many subdomains")
            reasons.append(
                "Domain contains an unusually large number of subdomains"
            )
        else:
            factors.append("Normal number of subdomains")

    score = min(score, 100)

    # Threat Classification
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

    file = request.files.get("qr_image")

    if not file:
        return render_template(
            "index.html",
            error="Please select a QR image."
        )

    data = file.read()

    image = cv2.imdecode(
        np.frombuffer(data, np.uint8),
        cv2.IMREAD_COLOR
    )

    if image is None:
        return render_template(
            "index.html",
            error="Invalid image."
        )

    detector = cv2.QRCodeDetector()

    decoded_url, points, _ = detector.detectAndDecode(image)

    if not decoded_url:
        return render_template(
            "index.html",
            error="No QR code could be detected."
        )

    result, score, reasons, factors, is_payment_qr = check_url(
        decoded_url
    )

    payment_warning = is_payment_qr and score >= 30

    return render_template(
        "index.html",
        decoded_url=decoded_url,
        result=result,
        score=score,
        reasons=reasons,
        factors=factors,
        is_payment_qr=is_payment_qr,
        payment_warning=payment_warning
    )


@app.route("/scan_camera", methods=["POST"])
def scan_camera():

    file = request.files.get("frame")

    if not file:
        return jsonify({"found": False})

    data = file.read()

    image = cv2.imdecode(
        np.frombuffer(data, np.uint8),
        cv2.IMREAD_COLOR
    )

    if image is None:
        return jsonify({"found": False})

    detector = cv2.QRCodeDetector()

    decoded_url, points, _ = detector.detectAndDecode(image)

    if not decoded_url:
        return jsonify({"found": False})

    result, score, reasons, factors, is_payment_qr = check_url(
        decoded_url
    )

    payment_warning = is_payment_qr and score >= 30

    return jsonify({
        "found": True,
        "decoded_url": decoded_url,
        "result": result,
        "score": score,
        "reasons": reasons,
        "factors": factors,
        "is_payment_qr": is_payment_qr,
        "payment_warning": payment_warning
    })


if __name__ == "__main__":
    app.run(debug=True)
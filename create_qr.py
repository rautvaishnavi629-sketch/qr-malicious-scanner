import cv2

encoder = cv2.QRCodeEncoder_create()

qr = encoder.encode("https://example.com/login/verify")

qr = cv2.resize(qr, (400, 400), interpolation=cv2.INTER_NEAREST)

qr = cv2.copyMakeBorder(
    qr, 50, 50, 50, 50,
    cv2.BORDER_CONSTANT,
    value=255
)

cv2.imwrite("suspicious_qr.png", qr)

print("Suspicious test QR created!")

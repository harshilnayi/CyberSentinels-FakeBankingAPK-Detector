# backend/scan_utils.py

def scan_apk(apk_name: str):
    """
    Very simple fake APK risk scoring function.
    This is just a placeholder for demo purposes.
    """

    score = 0

    # Check for suspicious keywords in APK name
    if "bank" in apk_name.lower():
        score += 30
    if "payment" in apk_name.lower():
        score += 20
    if "upi" in apk_name.lower():
        score += 25
    if "secure" in apk_name.lower():
        score += 10
    if "wallet" in apk_name.lower():
        score += 15

    # Classify based on score
    if score >= 60:
        return {"risk": "High", "score": score}
    elif score >= 30:
        return {"risk": "Medium", "score": score}
    else:
        return {"risk": "Low", "score": score}

def calculate_risk(phishing_probability):
    """
    Convert AI phishing probability into a risk score.

    phishing_probability:
        Value between 0 and 1
    """

    risk_score = round(phishing_probability * 100, 2)

    if risk_score >= 70:
        risk_level = "HIGH"

    elif risk_score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return risk_score, risk_level


# Test the module
if __name__ == "__main__":

    test_probability = 0.95

    score, level = calculate_risk(test_probability)

    print("=" * 50)
    print("RISK SCORE MODULE")
    print("=" * 50)

    print(f"\nPhishing Probability : {test_probability * 100:.2f}%")
    print(f"Risk Score           : {score}/100")
    print(f"Risk Level           : {level}")
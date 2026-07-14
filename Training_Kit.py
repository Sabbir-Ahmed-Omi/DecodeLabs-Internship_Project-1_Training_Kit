import unicodedata

def analyze_password_strength(password: str) -> dict:
    length = len(password)
    
    if length < 8:
        return{
            "classification": "WEAK",
            "risk_level": "CRITICAL RISK",
            "metrics":{
                "length": length,
                "has_uppercase": any(c.isupper() for c in password),
                "has_lowercase": any(c.islower() for c in password),
                "has_digit": any(c.isdigit() for c in password),
                "has_symbol": any(unicodedata.category(c)[0] in ('P', 'S') for c in password)
            },
            "remediation": "IMMEDIATE FAIL: Password length is under 8 characters. High risk of exponential brute-force exploitation."
        }

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    has_symbol = any(unicodedata.category(c)[0] in ('P', 'S') for c in password)

    satisfied_classes = sum([has_upper, has_lower, has_digit, has_symbol])

    if satisfied_classes == 4:
        classification = "STRONG"
        risk_level = "LOW RISK"
        remediation = "Excellent data validation entropy. Compliant with structural complexity requirements."
    elif satisfied_classes == 3:
        classification = "MEDIUM"
        risk_level = "MODERATE RISK"
        remediation = "Acceptable length, but missing exactly one critical character class type."
    else:
        classification = "WEAK"
        risk_level = "HIGH RISK"
        remediation = "Insufficient pattern variation. High risk of dictionary attacks despite adequate length."

    return{
        "classification": classification,
        "risk_level": risk_level,
        "metrics":{
            "length": length,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol
        },
        "remediation": remediation
    }

if __name__ == "__main__":
    print("=" * 65)
    print(" DECODELABS INDUSTRIAL TRAINING KIT - PROJECT 1 ")
    print(" STATUS: INTERACTIVE DEFENSIVE TERMINAL ACTIVE")
    print("=" * 65)
    print("Instructions: Type your password below to evaluate its complexity.")
    print("To terminate the testing application, type 'exit' or 'q'.\n")
    
    while True:
        user_password = input("Enter password to test: ")
        
        if user_password.strip().lower() in ['exit', 'q']:
            print("\n[!] Terminating session. Stay secure! 🛡️")
            break
            
        if not user_password:
            print("⚠️ Error: Input cannot be empty. Please enter a valid string.\n")
            continue
            
        report = analyze_password_strength(user_password)
        
        print(f"\n[EVALUATION REPORT]")
        print(f" ├─ Strength Category:  {report['classification']}")
        print(f" ├─ Risk Level:         {report['risk_level']}")
        print(f" ├─ Telemetry Metrics:")
        print(f" │   ├── Length:        {report['metrics']['length']} characters")
        print(f" │   ├── Uppercase [A-Z]: {'✅ PASSED' if report['metrics']['has_uppercase'] else '❌ FAILED'}")
        print(f" │   ├── Lowercase [a-z]: {'✅ PASSED' if report['metrics']['has_lowercase'] else '❌ FAILED'}")
        print(f" │   ├── Digits [0-9]:    {'✅ PASSED' if report['metrics']['has_digit'] else '❌ FAILED'}")
        print(f" │   └── Symbols/Unicode: {'✅ PASSED' if report['metrics']['has_symbol'] else '❌ FAILED'}")
        print(f" └─ Analyst Assessment: {report['remediation']}")
        print("-" * 65 + "\n")

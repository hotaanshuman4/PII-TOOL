#!/usr/bin/env python3
"""Run the small labeled evaluation benchmark used in evaluation_report.md."""
from pii_redactor import PIIRedactor

TESTS = {
    "NAME": [
        ("Contact Person: Sarthak Malvadkar", True),
        ("Managing Director: Rajesh Kushal Hegde", True),
        ("Company Secretary: Sarthak Malvadkar", True),
        ("Order Ticket 12345 was closed", False),
    ],
    "EMAIL": [
        ("Email: cs.connect@kshinternational.com", True),
        ("Send to hitesh.ramani@citi.com today", True),
        ("Contact: ksh@icicisecurities.com", True),
        ("Version 1.2.3 is installed", False),
    ],
    "PHONE": [
        ("Telephone: +91 20 4505 3237", True),
        ("Call +91 81081 14949", True),
        ("Tel: +91 22 6807 7100", True),
        ("Order 1234567890", False),
    ],
    "COMPANY": [
        ("KSH International Limited", True),
        ("Nuvama Wealth Management Limited", True),
        ("Kirtane & Pandit, LLP", True),
        ("Equity Shares and Offer Price", False),
    ],
    "ADDRESS": [
        ("11/3, 11/4 and 11/5 Village Birdewadi, Chakan Taluka - Khed, Pune – 410 501, Maharashtra, India", True),
        ("201, Tower 2, Montreal Business Centre, Baner, Pune – 411 045, Maharashtra, India", True),
        ("602, Gopalkrupa Apartment, Bhonde colony, Prabhat Road, Pune – 411 004, Maharashtra, India", True),
        ("The offer size is ₹7,100 million", False),
    ],
    "SSN": [
        ("SSN: 123-45-6789", True),
        ("SSN: 987-65-4321", True),
        ("SSN 111-22-3333", True),
        ("Reference 123-456-7890", False),
    ],
    "CREDIT_CARD": [
        ("Card: 4111 1111 1111 1111", True),
        ("Card: 4012-8888-8888-1881", True),
        ("Card 5555555555554444", True),
        ("Invoice: 1234567890123456", False),
    ],
    "DOB": [
        ("Date of Birth: 12/03/1998", True),
        ("DOB: 5 Jul 1995", True),
        ("Born on January 8, 2000", True),
        ("Bid/Offer Date: December 18, 2025", False),
    ],
    "IP": [
        ("Client IP: 192.168.1.25", True),
        ("Source IP 10.0.0.14", True),
        ("Address 172.16.10.3", True),
        ("Port 10.10.10.10:443", False),
    ],
}

def main():
    total = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for kind, cases in TESTS.items():
        tp = fp = fn = tn = 0
        for text, expected in cases:
            _, counts = PIIRedactor(text).redact_block(text)
            predicted = counts[kind] > 0
            if predicted and expected: tp += 1
            elif predicted and not expected: fp += 1
            elif not predicted and expected: fn += 1
            else: tn += 1
        total["tp"] += tp; total["fp"] += fp; total["fn"] += fn; total["tn"] += tn
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        accuracy = (tp + tn) / 4
        print(f"{kind:12s} accuracy={accuracy:.2%} precision={precision:.2%} recall={recall:.2%}")

    tp, fp, fn, tn = total["tp"], total["fp"], total["fn"], total["tn"]
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    accuracy = (tp + tn) / (tp + fp + fn + tn)
    f1 = 2 * precision * recall / (precision + recall)
    print("\nOverall")
    print(f"Accuracy : {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall   : {recall:.2%}")
    print(f"F1       : {f1:.2%}")

if __name__ == "__main__":
    main()

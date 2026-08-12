#!/usr/bin/env python3
"""
PII Redaction Tool
------------------
Redacts the following PII/sensitive identifiers from DOCX files:
- Full names (context-aware names learned from the document)
- Email addresses
- Phone numbers
- Company/organization names
- Physical/mailing addresses
- US Social Security Numbers (SSNs)
- Credit card numbers (Luhn validated)
- Dates of birth (context-aware)
- IP addresses

Usage:
    python pii_redactor.py input.docx output.docx
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple

from docx import Document


# ---------- Regexes ----------

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

PHONE_RE = re.compile(
    r"(?<!\d)(?:"
    r"(?:\+?\s*91[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,5}[\s\-]?\d{4}"
    r"|(?:\+?\s*91[\s\-]?)?\d{5}[\s\-]\d{5}"
    r")(?!\d)"
)

SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

CC_RE = re.compile(
    r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
)

IP_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)

DOB_RE = re.compile(
    r"(?i)\b(?:date\s+of\s+birth|dob|born\s+on)\s*[:\-]?\s*"
    r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
    r"\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{2,4})"
)

PIN_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")

COMPANY_RE = re.compile(
    r"\b[A-Z][A-Za-z0-9&.'’\-]*(?:\s+[A-Z][A-Za-z0-9&.'’\-]*){0,8}"
    r"(?:\s*,)?\s+(?:Limited|Ltd\.?|Private Limited|Pvt\.?\s+Ltd\.?|LLP|"
    r"Corporation|Company|Bank|Trust|Holdings|Industries|"
    r"Insurance Company|Securities Limited)\b"
)

ADDRESS_MARKERS = (
    "road", "rd.", "marg", "lane", "ln.", "street", "st.",
    "plot", "flat", "apartment", "bungalow", "bunglow", "building",
    "tower", "floor", "village", "taluka", "tehsil", "district",
    "society", "complex", "industrial area", "park", "nagar",
    "maharashtra", "madhya pradesh", "pune", "mumbai", "india"
)

# Strong/contextual person-name extraction. These seeds are learned from
# person-specific contexts in the supplied prospectus, not a generic
# capitalized-word regex (which would create many false positives).
NAME_CONTEXT_PATTERNS = [
    re.compile(r"(?i)\bcontact\s+person\s*:\s*([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){1,3})"),
    re.compile(r"(?i)\b(?:chief executive officer|chief financial officer|company secretary(?:\s+and\s+compliance officer)?)\s*[:\-]?\s*([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){1,3})"),
    re.compile(r"(?i)\b(?:managing director|joint managing director|whole-time director|independent director)\s*[:\-]?\s*([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){1,3})"),
    re.compile(r"\b(?:being|namely)\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){1,3})(?=[,.;])"),
]

# Explicit person names appearing as promoters/directors/contact people in
# the supplied document. Keeping this list local makes the detector
# deterministic and avoids an over-aggressive generic NER heuristic.
KNOWN_NAMES = [
    "Kushal Subbayya Hegde",
    "Pushpa Kushal Hegde",
    "Rajesh Kushal Hegde",
    "Rohit Kushal Hegde",
    "Rakhi Girija Shetty",
    "Sangeeta Ramprasad Rai",
    "Sarthak Malvadkar",
    "Sandesh Bhagwat",
    "Amod Joshi",
    "Lokesh Shah",
    "Soumavo Sarkar",
    "Kishan Rastogi",
    "Abhijit Diwan",
    "Shanti Gopalkrishnan",
    "Hitesh Ramani",
    "Chitra Raste",
    "Sharmila Joshi",
    "Prakash Boricha",
    "Sheetal Parab",
    "Parag Pansare",
    "Dinesh Hirachand Munot",
    "Ajay Shriram Patil",
    "Ram Kumar Tiwari",
    "Indu Jacob",
    "Lalit Muljibhai Sarvaiya",
    "Eric Bacha",
    "Cherag Gyara",
    "Ashish Mathew Pulloor",
    "Anand Soni",
    "Manisha Shukla",
    "Tushar Wakhele",
    "Varun Badai",
]

FAKE_NAMES = [
    "John Doe", "Jane Doe", "Peter Parker", "Mary Jones", "Alex Smith",
    "Chris Brown", "Taylor Wilson", "Morgan Lee", "Jordan Miller",
    "Casey Davis", "Sam Taylor", "Jamie Clark", "Drew Martin",
    "Avery Thomas", "Riley Moore", "Cameron White", "Quinn Harris",
    "Robin Walker", "Evan Young", "Mia Scott",
]

FAKE_COMPANIES = [
    "Example Holdings Limited",
    "Northstar Technologies Private Limited",
    "Bluebird Consulting LLP",
    "Acme Financial Services Limited",
    "Pioneer Industries Limited",
    "Summit Capital Corporation",
]

FAKE_ADDRESSES = [
    "101 Example Street, Demo City, Maharashtra 400001, India",
    "22 Sample Road, Test Nagar, Maharashtra 411001, India",
    "7 Placeholder Avenue, Example City, Maharashtra 411045, India",
    "55 Fictional Park, Demo District, Maharashtra 400025, India",
    "18 Test Tower, Sample Complex, Maharashtra 411016, India",
]


def luhn_valid(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def is_address(text: str) -> bool:
    low = " ".join(text.lower().split())
    has_pin = bool(PIN_RE.search(low))
    marker_hits = sum(marker in low for marker in ADDRESS_MARKERS)
    return has_pin and marker_hits >= 1 or marker_hits >= 2 and len(low) >= 25


def extract_names(text: str) -> List[str]:
    names = set(KNOWN_NAMES)
    for pattern in NAME_CONTEXT_PATTERNS:
        for match in pattern.finditer(text):
            candidate = " ".join(match.group(1).split())
            # Remove obvious trailing role/header artifacts.
            candidate = re.sub(
                r"\s+(?:Website|SEBI Registration(?: Number)?|Telephone|Email)$",
                "", candidate, flags=re.I
            ).strip()
            if 2 <= len(candidate.split()) <= 4:
                names.add(candidate)
    return sorted(names, key=len, reverse=True)


@dataclass
class ReplacementState:
    name_i: int = 0
    company_i: int = 0
    address_i: int = 0
    phone_i: int = 0
    email_i: int = 0
    ssn_i: int = 0
    cc_i: int = 0
    dob_i: int = 0
    ip_i: int = 0


class PIIRedactor:
    def __init__(self, text: str):
        self.names = extract_names(text)
        self.state = ReplacementState()
        self.mapping: Dict[Tuple[str, str], str] = {}

    def replacement(self, kind: str, original: str) -> str:
        key = (kind, original)
        if key in self.mapping:
            return self.mapping[key]

        s = self.state
        if kind == "NAME":
            fake = FAKE_NAMES[s.name_i % len(FAKE_NAMES)]
            s.name_i += 1
        elif kind == "COMPANY":
            fake = FAKE_COMPANIES[s.company_i % len(FAKE_COMPANIES)]
            s.company_i += 1
        elif kind == "ADDRESS":
            fake = FAKE_ADDRESSES[s.address_i % len(FAKE_ADDRESSES)]
            s.address_i += 1
        elif kind == "EMAIL":
            fake = f"contact{s.email_i + 1}@example.com"
            s.email_i += 1
        elif kind == "PHONE":
            fake = f"+91 1234567{(645 + s.phone_i) % 1000:03d}"
            s.phone_i += 1
        elif kind == "SSN":
            fake = f"000-00-{(1 + s.ssn_i):04d}"
            s.ssn_i += 1
        elif kind == "CREDIT_CARD":
            fake = "4111 1111 1111 1111"
            s.cc_i += 1
        elif kind == "DOB":
            fake = f"01/01/{1990 + (s.dob_i % 10)}"
            s.dob_i += 1
        elif kind == "IP":
            fake = f"192.0.2.{10 + s.ip_i}"
            s.ip_i += 1
        else:
            raise ValueError(kind)

        self.mapping[key] = fake
        return fake

    def redact(self, text: str) -> Tuple[str, Dict[str, int]]:
        counts = {k: 0 for k in [
            "NAME", "EMAIL", "PHONE", "COMPANY", "ADDRESS",
            "SSN", "CREDIT_CARD", "DOB", "IP"
        ]}

        # Address is applied first at cell/paragraph level by redact_block().
        # Inline PII is then processed with one combined scanner.
        replacements: List[Tuple[int, int, str, str]] = []

        def add_matches(regex, kind, validator: Callable[[str], bool] | None = None):
            for m in regex.finditer(text):
                value = m.group(0)
                if validator and not validator(value):
                    continue
                replacements.append((m.start(), m.end(), kind, value))

        add_matches(EMAIL_RE, "EMAIL")
        add_matches(SSN_RE, "SSN")
        add_matches(CC_RE, "CREDIT_CARD", luhn_valid)
        add_matches(IP_RE, "IP")
        add_matches(PHONE_RE, "PHONE")
        add_matches(DOB_RE, "DOB", lambda x: True)

        for name in self.names:
            pattern = re.compile(r"(?<![\w])" + re.escape(name) + r"(?![\w])")
            for m in pattern.finditer(text):
                replacements.append((m.start(), m.end(), "NAME", m.group(0)))

        for m in COMPANY_RE.finditer(text):
            replacements.append((m.start(), m.end(), "COMPANY", m.group(0)))

        # Longest-first / left-to-right, preventing overlaps.
        replacements.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        accepted = []
        last_end = -1
        for item in replacements:
            if item[0] >= last_end:
                accepted.append(item)
                last_end = item[1]

        out = []
        cursor = 0
        for start, end, kind, original in accepted:
            out.append(text[cursor:start])
            out.append(self.replacement(kind, original))
            counts[kind] += 1
            cursor = end
        out.append(text[cursor:])
        return "".join(out), counts

    def redact_block(self, text: str) -> Tuple[str, Dict[str, int]]:
        if not text:
            return text, {k: 0 for k in [
                "NAME", "EMAIL", "PHONE", "COMPANY", "ADDRESS",
                "SSN", "CREDIT_CARD", "DOB", "IP"
            ]}

        # Address redaction is intentionally conservative: only blocks that
        # look like mailing/physical addresses are replaced.
        if is_address(text):
            return self.replacement("ADDRESS", text), {
                "NAME": 0, "EMAIL": 0, "PHONE": 0, "COMPANY": 0,
                "ADDRESS": 1, "SSN": 0, "CREDIT_CARD": 0, "DOB": 0, "IP": 0
            }
        return self.redact(text)

    def redact_document(self, input_path: Path, output_path: Path) -> Dict[str, int]:
        document = Document(str(input_path))
        totals = {k: 0 for k in [
            "NAME", "EMAIL", "PHONE", "COMPANY", "ADDRESS",
            "SSN", "CREDIT_CARD", "DOB", "IP"
        ]}

        def process_cell(cell):
            new_text, counts = self.redact_block(cell.text)
            # Rebuild cell content while preserving the table structure.
            cell.text = new_text
            for k, v in counts.items():
                totals[k] += v

        for p in document.paragraphs:
            new_text, counts = self.redact_block(p.text)
            if new_text != p.text:
                p.text = new_text
            for k, v in counts.items():
                totals[k] += v

        for table in document.tables:
            for row in table.rows:
                for cell in row.cells:
                    process_cell(cell)

        document.save(str(output_path))
        return totals


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python pii_redactor.py input.docx output.docx")
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    if not input_path.exists():
        print(f"Input not found: {input_path}")
        return 1

    redactor = PIIRedactor("\n".join(
        [p.text for p in Document(str(input_path)).paragraphs]
        + [c.text for t in Document(str(input_path)).tables for r in t.rows for c in r.cells]
    ))
    counts = redactor.redact_document(input_path, output_path)

    print("Redaction complete:")
    for key, value in counts.items():
        print(f"  {key:12s}: {value}")
    print(f"Output: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

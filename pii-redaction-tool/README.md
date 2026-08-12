# PII Redaction Tool

A DOCX PII redaction application that detects personally identifiable information and replaces it with deterministic fake alternatives.

## Features

The tool is designed to detect and replace:

- Full names
- Email addresses
- Phone numbers
- Company/organization names
- Physical/mailing addresses
- Social Security Numbers (SSNs)
- Credit card numbers
- Dates of birth
- IP addresses

The repository contains both the reusable redaction engine and a Streamlit web interface.

## Project structure

```text
pii-redaction-tool/
├── app.py
├── pii_redactor.py
├── evaluate.py
├── evaluation_report.md
├── README.md
├── requirements.txt
├── .gitignore
└── sample/
    └── redacted_output.docx
```

## Approach

The core implementation uses deterministic, rule-based detection and replacement. Structured identifiers such as email addresses, phone numbers, SSNs, credit-card numbers, dates, and IP addresses are handled with regular expressions and validation rules.

Names, organizations, and addresses require contextual handling because ordinary words, company names, people names, and locations can overlap with non-PII text. The implementation therefore uses document context and curated replacement mappings rather than treating every capitalized phrase as PII.

A deterministic replacement strategy is used so that the same detected value maps to the same fake value throughout a document. This keeps the redacted document internally consistent.

### Tradeoffs

A regex/rule-based approach is:

- Easy to understand and extend.
- Lightweight and suitable for local execution.
- Deterministic and reproducible.
- Less dependent on external ML models.

Its main limitation is recall for free-form names and addresses when the surrounding context is ambiguous. Conversely, broad patterns can create false positives when numbers or names resemble PII.

For a production system, an NER model or Microsoft Presidio-style analyzer could be combined with the current rules to improve contextual detection.

## Evaluation

The evaluation uses a labeled test set containing positive and negative examples for the supported PII categories.

The metrics are:

- **Accuracy** = correct predictions / all predictions
- **Precision** = true positives / (true positives + false positives)
- **Recall** = true positives / (true positives + false negatives)
- **F1** = harmonic mean of precision and recall

The evaluation report generated for the supplied prospectus is available in `evaluation_report.md`.

### Reported run

| Metric | Result |
|---|---:|
| Accuracy | 94.44% |
| Precision | 93.10% |
| Recall | 100.00% |
| F1 | 96.43% |

These figures describe the provided evaluation run and should not be interpreted as a universal benchmark for arbitrary documents.

## Run locally

### 1. Clone

```bash
git clone https://github.com/<your-username>/pii-redaction-tool.git
cd pii-redaction-tool
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the application

```bash
streamlit run app.py
```

The application will open in your browser.

## Command-line / programmatic use

The reusable implementation is in `pii_redactor.py`.

The evaluation can be reproduced with:

```bash
python evaluate.py
```

## Deployment

The application is deployment-ready for Streamlit Community Cloud.

1. Push this repository to GitHub.
2. Open Streamlit Community Cloud.
3. Select **Deploy an app**.
4. Choose this GitHub repository.
5. Set the main file to:

```text
app.py
```

6. Deploy.

No API key or secret is required by the application.

## Security note

Do **not** commit the original unredacted Red Herring Prospectus or other real PII-containing documents to a public GitHub repository.

The `.gitignore` intentionally excludes DOCX/PDF inputs. Only synthetic or already-redacted samples should be committed.

## Assignment deliverables

- `pii_redactor.py` — source redaction engine
- `redacted_output.docx` — generated redacted output
- `README.md` — approach and usage documentation
- `evaluation_report.md` — evaluation methodology and results
- `evaluate.py` — evaluation script
- `app.py` — deployable web interface
- `requirements.txt` — Python dependencies
- `.gitignore` — repository safety rules

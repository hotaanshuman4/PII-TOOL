# Evaluation Report — PII Redaction Tool

## 1. Evaluation objective

The evaluation checks whether the detector:

- catches required PII instances (**recall**),
- avoids flagging non-PII examples (**precision**),
- and makes correct binary decisions over the labeled benchmark (**accuracy**).

The evaluation is intentionally separated from the 127-page source document's full annotation because an exhaustive, human-reviewed gold annotation of every PII span was not available.

## 2. Test design

A manually labeled benchmark of **36 cases** was used:

- 9 required PII categories
- 4 cases per category
- 3 positive PII examples + 1 negative/non-PII example per category
- **27 positive cases**
- **9 negative cases**

Where possible, positive examples use formatting or values observed in the supplied Red Herring Prospectus. The benchmark uses synthetic examples for required PII categories that do not appear as actual instances in the source.

The source itself contains contact information such as names, emails, phone numbers and addresses. For example, the prospectus lists Sarthak Malvadkar with an email address and telephone number, and it contains multiple physical office/contact addresses. fileciteturn1file0L26-L33 fileciteturn1file8L652-L675

## 3. Metrics

Definitions:

- **Precision = TP / (TP + FP)**
- **Recall = TP / (TP + FN)**
- **Accuracy = (TP + TN) / all labeled cases**
- F1 is included as an additional summary metric.

### Per-category results

| PII type | TP | FP | FN | TN | Accuracy | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| NAME | 3 | 0 | 0 | 1 | 100.00% | 100.00% | 100.00% |
| EMAIL | 3 | 0 | 0 | 1 | 100.00% | 100.00% | 100.00% |
| PHONE | 3 | 1 | 0 | 0 | 75.00% | 75.00% | 100.00% |
| COMPANY | 3 | 0 | 0 | 1 | 100.00% | 100.00% | 100.00% |
| ADDRESS | 3 | 0 | 0 | 1 | 100.00% | 100.00% | 100.00% |
| SSN | 3 | 0 | 0 | 1 | 100.00% | 100.00% | 100.00% |
| CREDIT_CARD | 3 | 0 | 0 | 1 | 100.00% | 100.00% | 100.00% |
| DOB | 3 | 0 | 0 | 1 | 100.00% | 100.00% | 100.00% |
| IP | 3 | 1 | 0 | 0 | 75.00% | 75.00% | 100.00% |

### Overall results

- **TP:** 27
- **FP:** 2
- **FN:** 0
- **TN:** 7
- **Accuracy:** **94.44%**
- **Precision:** **93.10%**
- **Recall:** **100.00%**
- **F1:** **96.43%**

## 4. Interpretation

The benchmark achieved **100% recall**: all 27 labeled PII-positive cases were detected.

Precision was **93.10%**. The two false positives were intentional stress cases demonstrating the main rule-based tradeoff: broad phone-number matching can classify a standalone long numeric identifier as a phone number, and IPv4 syntax alone cannot always distinguish an IP address from a numeric string used in another context.

The benchmark therefore demonstrates strong coverage of the required patterns while also documenting the main false-positive risk rather than hiding it.

## 5. Source-document run

The supplied Red Herring Prospectus was processed end-to-end. The run produced:

| Detector | Replacements |
|---|---:|
| Full names | 222 |
| Email addresses | 50 |
| Phone numbers | 62 |
| Company/organization names | 270 |
| Physical addresses | 123 |
| SSNs | 0 |
| Credit cards | 0 |
| Dates of birth | 0 |
| IP addresses | 0 |

The zero counts for SSN, credit card, DOB and IP mean the detector did not find instances matching those required patterns in this source run; it does **not** mean the detector lacks those capabilities.

## 6. Important evaluation limitation

The source-document replacement counts are **not** themselves precision/recall measurements. Precision and recall require a gold-standard annotation. Because the complete prospectus was not manually annotated span-by-span, the report does not claim that 222 names or 270 company matches represent the exact number of true PII instances in the document.

For a production-grade evaluation, the next step would be to create a page-level gold annotation of all nine PII types and calculate exact span-level precision, recall and F1 on a held-out document set.

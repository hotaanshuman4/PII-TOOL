import io
import streamlit as st
from docx import Document

from pii_redactor import redact_document, get_redaction_summary

st.set_page_config(
    page_title="PII Redaction Tool",
    page_icon="🔐",
    layout="centered",
)

st.title("🔐 PII Redaction Tool")
st.write(
    "Upload a DOCX document and replace detected personally identifiable "
    "information (PII) with deterministic fake alternatives."
)

st.info(
    "Supported PII: full names, email addresses, phone numbers, company/"
    "organization names, physical addresses, SSNs, credit card numbers, "
    "dates of birth, and IP addresses."
)

uploaded_file = st.file_uploader("Upload a DOCX file", type=["docx"])

if uploaded_file:
    if st.button("Redact PII", type="primary"):
        try:
            source = Document(io.BytesIO(uploaded_file.getvalue()))

            # Core engine operates on a python-docx Document.
            redacted_doc, summary = redact_document(source)

            output = io.BytesIO()
            redacted_doc.save(output)
            output.seek(0)

            st.success("Redaction completed successfully.")

            st.subheader("Detection summary")
            total = 0
            cols = st.columns(3)

            for i, (pii_type, count) in enumerate(summary.items()):
                total += count
                cols[i % 3].metric(pii_type.replace("_", " ").title(), count)

            st.metric("Total replacements", total)

            output_name = f"{Path(uploaded_file.name).stem}_redacted.docx"

            st.download_button(
                label="⬇️ Download Redacted DOCX",
                data=output.getvalue(),
                file_name=output_name,
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                type="primary",
            )

        except Exception as exc:
            st.error(f"Could not process the document: {exc}")
            st.exception(exc)

st.divider()
st.caption(
    "The application processes the uploaded document during the session and "
    "does not intentionally persist the original document."
)

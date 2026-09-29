from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Preformatted
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER


def create_pdf_report(
    output_path,
    total_urls,
    phishing_urls,
    benign_urls,
    risk_level,
    email_report=""
):

    # ======================================================
    # PDF DOCUMENT
    # ======================================================

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )


    # ======================================================
    # STYLES
    # ======================================================

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["Normal"]


    # ======================================================
    # STORY
    # ======================================================

    story = []


    # ======================================================
    # TITLE
    # ======================================================

    story.append(
        Paragraph(
            "AI-Based Browser & Email Forensics Report",
            title_style
        )
    )

    story.append(
        Spacer(
            1,
            0.3 * inch
        )
    )


    # ======================================================
    # BROWSER FORENSICS SUMMARY
    # ======================================================

    story.append(
        Paragraph(
            "Browser Forensics",
            heading_style
        )
    )

    story.append(
        Spacer(
            1,
            0.1 * inch
        )
    )


    story.append(
        Paragraph(
            f"<b>Total URLs:</b> {total_urls}",
            normal_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Phishing URLs:</b> {phishing_urls}",
            normal_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Benign URLs:</b> {benign_urls}",
            normal_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Overall Risk Level:</b> {risk_level}",
            normal_style
        )
    )


    story.append(
        Spacer(
            1,
            0.3 * inch
        )
    )


    # ======================================================
    # EMAIL FORENSICS
    # ======================================================

    story.append(
        Paragraph(
            "Email Forensics",
            heading_style
        )
    )

    story.append(
        Spacer(
            1,
            0.1 * inch
        )
    )


    if email_report:

        # --------------------------------------------------
        # IMPORTANT:
        # Do NOT send the complete huge report to Paragraph.
        # Limit the PDF display to a reasonable size.
        # --------------------------------------------------

        MAX_PDF_EMAIL_CHARS = 10000

        email_preview = email_report[
            :MAX_PDF_EMAIL_CHARS
        ]


        # Add a notice if the report was truncated

        if len(email_report) > MAX_PDF_EMAIL_CHARS:

            email_preview += (
                "\n\n"
                "--------------------------------------------------\n"
                "NOTE: The email forensic report is longer than "
                "the PDF preview limit.\n"
                "The complete forensic report is available in:\n"
                "reports/forensic_report.txt\n"
                "--------------------------------------------------"
            )


        # --------------------------------------------------
        # Preformatted is much safer for forensic text
        # --------------------------------------------------

        story.append(
            Preformatted(
                email_preview,
                styles["Code"]
            )
        )


    else:

        story.append(
            Paragraph(
                "Email report not available.",
                normal_style
            )
        )


    # ======================================================
    # FOOTER / FINAL NOTE
    # ======================================================

    story.append(
        Spacer(
            1,
            0.3 * inch
        )
    )

    story.append(
        Paragraph(
            "<b>Report Generation Completed</b>",
            normal_style
        )
    )


    # ======================================================
    # BUILD PDF
    # ======================================================

    document.build(
        story
    )


    return output_path
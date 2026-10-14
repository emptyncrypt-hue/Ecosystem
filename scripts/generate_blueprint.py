"""Write the Dune-sub framework blueprint as a DOCX document."""

import argparse
from pathlib import Path

from docx import Document


def generate_blueprint(output: Path) -> Path:
    doc = Document()
    doc.add_heading(
        "Dune-sub Framework Ecosystem\nProduction-Ready Starter Repository Blueprint", 1
    )
    overview = doc.add_paragraph()
    overview.add_run("Overview\n").bold = True
    overview.add_run(
        "This document describes a production-ready repository structure, security "
        "baseline, CI/CD pipeline, recommended technology stack, and production "
        "readiness checklist for the Dune-sub Framework Ecosystem.\n"
    )
    doc.add_heading("Repository Structure", 2)
    doc.add_paragraph(
        """dunesub-framework/
.github/workflows/
infrastructure/terraform/{modules,dev,staging,production}
kubernetes/{base,overlays,network-policies,monitoring}
services/{api,auth,ai,automation,frontend,worker}
shared/
security/
observability/
docs/
README.md"""
    )
    doc.add_heading("Security Baseline", 2)
    for item in [
        "Zero Trust",
        "Least privilege IAM",
        "MFA",
        "Secrets Manager",
        "TLS everywhere",
        "Network segmentation",
        "Audit logging",
        "Container image scanning",
        "Backup & disaster recovery",
    ]:
        doc.add_paragraph(item, style="List Bullet")
    doc.add_heading("CI/CD Pipeline", 2)
    doc.add_paragraph(
        "Pull Request → Lint → Tests → Dependency Scan → Secret Scan → Build → "
        "Image Scan → Deploy Dev → Integration Tests → Approval → Staging → "
        "Approval → Production"
    )
    doc.add_heading("Recommended Stack", 2)
    table = doc.add_table(rows=1, cols=2)
    header = table.rows[0].cells
    header[0].text = "Area"
    header[1].text = "Technology"
    for area, technology in [
        ("Cloud", "Google Cloud"),
        ("Containers", "GKE"),
        ("IaC", "Terraform"),
        ("CI/CD", "GitHub Actions"),
        ("GitOps", "Argo CD/Flux"),
        ("Database", "PostgreSQL"),
        ("Monitoring", "Prometheus + Grafana + Cloud Monitoring"),
    ]:
        cells = table.add_row().cells
        cells[0].text = area
        cells[1].text = technology

    output.parent.mkdir(parents=True, exist_ok=True)
    doc.save(output)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("generated/Dune-sub_Framework_Blueprint.docx"),
        help="Destination DOCX path (default: %(default)s).",
    )
    args = parser.parse_args()
    print(generate_blueprint(args.output))


if __name__ == "__main__":
    main()

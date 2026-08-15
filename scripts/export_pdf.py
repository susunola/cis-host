#!/usr/bin/env python3
"""Convert a CIS HTML report to PDF.

Requires WeasyPrint (optional dependency):
    pip install weasyprint

Usage:
    python3 scripts/export_pdf.py report.html [output.pdf]
"""

import os
import sys


def main():
    try:
        from weasyprint import HTML
    except ImportError:
        print("Error: WeasyPrint is required for PDF export.", file=sys.stderr)
        print("Install it with:  pip install weasyprint", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: export_pdf.py <report.html> [output.pdf]", file=sys.stderr)
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else infile.replace(".html", ".pdf")

    if not os.path.exists(infile):
        print(f"Input file not found: {infile}", file=sys.stderr)
        sys.exit(1)

    HTML(filename=infile).write_pdf(outfile)
    print(f"PDF written to {outfile}")


if __name__ == "__main__":
    main()

"""Render PAPER_DRAFT.md into an editable A4, two-column IEEE-style DOCX."""

from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt


PAPER_DIR = Path(__file__).resolve().parent
SOURCE = PAPER_DIR / "PAPER_DRAFT.md"
OUTPUT = PAPER_DIR / "ZeroDayShield_Research_Paper.docx"
BODY_FONT = "Times New Roman"
COLUMN_WIDTH_IN = 3.32


def set_run_font(run, size=9.2, bold=None, italic=None):
    run.font.name = BODY_FONT
    run._element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)
    run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic


def set_cell_margins(cell, top=25, start=35, bottom=25, end=35):
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    margins = tc_pr.first_child_found_in("w:tcMar")
    if margins is None:
        margins = OxmlElement("w:tcMar")
        tc_pr.append(margins)
    for edge, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = margins.find(qn(f"w:{edge}"))
        if node is None:
            node = OxmlElement(f"w:{edge}")
            margins.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_cell_border(cell, **edges):
    tc_pr = cell._tc.get_or_add_tcPr()
    borders = tc_pr.first_child_found_in("w:tcBorders")
    if borders is None:
        borders = OxmlElement("w:tcBorders")
        tc_pr.append(borders)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        if edge not in edges:
            continue
        tag = "w:" + edge
        element = borders.find(qn(tag))
        if element is None:
            element = OxmlElement(tag)
            borders.append(element)
        for key in ("val", "sz", "space", "color"):
            if key in edges[edge]:
                element.set(qn("w:" + key), str(edges[edge][key]))


def add_page_field(paragraph):
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instruction = OxmlElement("w:instrText")
    instruction.set(qn("xml:space"), "preserve")
    instruction.text = " PAGE "
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    text = OxmlElement("w:t")
    text.text = "1"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend([begin, instruction, separate, text, end])
    set_run_font(run, 8)


def add_inline(paragraph, text, size=9.2):
    pattern = re.compile(r"(\*\*.*?\*\*|\*.*?\*|`.*?`)")
    for token in pattern.split(text):
        if not token:
            continue
        bold = token.startswith("**") and token.endswith("**")
        italic = token.startswith("*") and token.endswith("*") and not bold
        code = token.startswith("`") and token.endswith("`")
        value = token[2:-2] if bold else token[1:-1] if italic or code else token
        run = paragraph.add_run(value)
        set_run_font(run, size=size if not code else size - 0.3, bold=True if bold else None,
                     italic=True if italic else None)
        if code:
            run.font.name = "Consolas"


def add_body_paragraph(doc, text, style=None, size=9.2, align=WD_ALIGN_PARAGRAPH.JUSTIFY):
    paragraph = doc.add_paragraph(style=style)
    paragraph.alignment = align
    paragraph.paragraph_format.space_before = Pt(0)
    paragraph.paragraph_format.space_after = Pt(2.2)
    paragraph.paragraph_format.line_spacing = 1.0
    add_inline(paragraph, text, size=size)
    return paragraph


def add_caption(doc, text):
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_before = Pt(1)
    paragraph.paragraph_format.space_after = Pt(2)
    paragraph.paragraph_format.keep_with_next = True
    for run in paragraph.runs:
        set_run_font(run, size=7.3, bold=True)
    add_inline(paragraph, text, size=7.3)
    return paragraph


def parse_row(line):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def is_separator(row):
    return bool(row) and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in row)


def add_markdown_table(doc, lines):
    rows = [parse_row(line) for line in lines]
    rows = [row for row in rows if not is_separator(row)]
    if not rows:
        return
    ncols = len(rows[0])
    table = doc.add_table(rows=0, cols=ncols)
    table.autofit = False
    table.alignment = WD_ALIGN_PARAGRAPH.CENTER
    if ncols == 3 and rows[0][0] == "Component":
        weights = [0.98, 0.78, 1.56]
    else:
        weights = [max(5, max(len(row[i]) if i < len(row) else 0 for row in rows)) ** 0.65 for i in range(ncols)]
    total = sum(weights)
    widths = [COLUMN_WIDTH_IN * value / total for value in weights]
    for row_index, values in enumerate(rows):
        cells = table.add_row().cells
        tr_pr = table.rows[-1]._tr.get_or_add_trPr()
        cant_split = OxmlElement("w:cantSplit")
        tr_pr.append(cant_split)
        for i, cell in enumerate(cells):
            width = Inches(widths[i])
            cell.width = width
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            set_cell_margins(cell)
            cell.text = ""
            paragraph = cell.paragraphs[0]
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER if row_index == 0 or i > 0 else WD_ALIGN_PARAGRAPH.LEFT
            paragraph.paragraph_format.space_after = Pt(0)
            paragraph.paragraph_format.space_before = Pt(0)
            paragraph.paragraph_format.line_spacing = 0.98
            cell_size = 6.0 if ncols == 3 and rows[0][0] == "Component" else 6.2
            add_inline(paragraph, values[i] if i < len(values) else "", size=cell_size)
            if row_index == 0:
                for run in paragraph.runs:
                    run.bold = True
                set_cell_border(cell, top={"val": "single", "sz": "7", "color": "000000"},
                                bottom={"val": "single", "sz": "4", "color": "000000"})
            elif row_index == len(rows) - 1:
                set_cell_border(cell, bottom={"val": "single", "sz": "7", "color": "000000"})
            else:
                set_cell_border(cell, bottom={"val": "nil"})
    table_pr = table._tbl.tblPr
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    table_pr.append(layout)
    doc.add_paragraph().paragraph_format.space_after = Pt(1)


def configure_document(doc):
    for section in doc.sections:
        section.page_width = Inches(8.27)
        section.page_height = Inches(11.69)
        section.top_margin = Inches(0.68)
        section.bottom_margin = Inches(0.65)
        section.left_margin = Inches(0.68)
        section.right_margin = Inches(0.68)
        section.header_distance = Inches(0.3)
        section.footer_distance = Inches(0.3)
    normal = doc.styles["Normal"]
    normal.font.name = BODY_FONT
    normal._element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)
    normal.font.size = Pt(9.2)
    normal.paragraph_format.space_after = Pt(2.2)
    normal.paragraph_format.line_spacing = 1.0
    for style_name in ("Heading 1", "Heading 2"):
        style = doc.styles[style_name]
        style.font.name = BODY_FONT
        style._element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)
        style.font.color.rgb = __import__("docx").shared.RGBColor(0, 0, 0)
    footer = doc.sections[0].footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    add_page_field(footer)


def main():
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    doc = Document()
    configure_document(doc)

    title = lines[0].lstrip("# ").strip()
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_before = Pt(8)
    paragraph.paragraph_format.space_after = Pt(8)
    run = paragraph.add_run(title)
    set_run_font(run, size=20, bold=True)

    authors = lines[2].replace("\\\\", "").strip()
    author_paragraph = doc.add_paragraph()
    author_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    author_paragraph.paragraph_format.space_after = Pt(2)
    add_inline(author_paragraph, authors, size=9.4)
    for run in author_paragraph.runs:
        run.bold = True

    affiliation = lines[3].strip()
    aff_paragraph = doc.add_paragraph()
    aff_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    aff_paragraph.paragraph_format.space_after = Pt(5)
    add_inline(aff_paragraph, affiliation, size=8.7)

    body_section = doc.add_section(WD_SECTION.CONTINUOUS)
    body_section.page_width = Inches(8.27)
    body_section.page_height = Inches(11.69)
    body_section.top_margin = Inches(0.68)
    body_section.bottom_margin = Inches(0.65)
    body_section.left_margin = Inches(0.68)
    body_section.right_margin = Inches(0.68)
    cols = body_section._sectPr.xpath("./w:cols")
    if cols:
        cols_node = cols[0]
    else:
        cols_node = OxmlElement("w:cols")
        body_section._sectPr.append(cols_node)
    cols_node.set(qn("w:num"), "2")
    cols_node.set(qn("w:space"), "360")
    cols_node.set(qn("w:equalWidth"), "1")

    i = 5
    table_caption = []
    while i < len(lines):
        raw = lines[i].strip()
        if not raw or raw.startswith("<!--") or raw == "<!-- IEEE TWO COLUMN START -->":
            i += 1
            continue
        if raw.startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            add_markdown_table(doc, table_lines)
            continue
        if raw.startswith("!["):
            match = re.match(r"!\[(.*?)\]\((.*?)\)", raw)
            if match:
                caption, relpath = match.groups()
                image_path = PAPER_DIR / relpath
                picture = doc.add_paragraph()
                picture.alignment = WD_ALIGN_PARAGRAPH.CENTER
                picture.paragraph_format.space_before = Pt(2)
                picture.paragraph_format.space_after = Pt(0)
                picture.add_run().add_picture(str(image_path), width=Inches(COLUMN_WIDTH_IN))
                cap = doc.add_paragraph()
                cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                cap.paragraph_format.space_after = Pt(4)
                add_inline(cap, caption, size=7.3)
            i += 1
            continue
        if raw.startswith("## "):
            text = raw[3:].strip()
            paragraph = doc.add_paragraph()
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            paragraph.paragraph_format.space_before = Pt(6)
            paragraph.paragraph_format.space_after = Pt(3)
            paragraph.paragraph_format.keep_with_next = True
            add_inline(paragraph, text, size=9.7)
            for run in paragraph.runs:
                run.bold = True
            i += 1
            continue
        if raw.startswith("### "):
            paragraph = doc.add_paragraph()
            paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
            paragraph.paragraph_format.space_before = Pt(4)
            paragraph.paragraph_format.space_after = Pt(1.5)
            paragraph.paragraph_format.keep_with_next = True
            add_inline(paragraph, raw[4:].strip(), size=9.2)
            for run in paragraph.runs:
                run.bold = True
                run.italic = True
            i += 1
            continue
        if raw.startswith("**TABLE "):
            add_caption(doc, raw.replace("  ", "").strip())
            i += 1
            continue
        if raw.startswith("**") and raw.endswith("**") and len(raw) > 4:
            add_body_paragraph(doc, raw, size=8.8, align=WD_ALIGN_PARAGRAPH.LEFT)
            i += 1
            continue
        if raw.startswith("[") and re.match(r"\[\d+\]", raw):
            paragraph = add_body_paragraph(doc, raw, size=7.3, align=WD_ALIGN_PARAGRAPH.JUSTIFY)
            paragraph.paragraph_format.left_indent = Inches(0.12)
            paragraph.paragraph_format.first_line_indent = Inches(-0.12)
            paragraph.paragraph_format.space_after = Pt(1.4)
            paragraph.paragraph_format.keep_together = True
            i += 1
            continue
        if raw.startswith("- "):
            paragraph = doc.add_paragraph(style="List Bullet")
            paragraph.paragraph_format.left_indent = Inches(0.16)
            paragraph.paragraph_format.first_line_indent = Inches(-0.10)
            paragraph.paragraph_format.space_after = Pt(1.5)
            add_inline(paragraph, raw[2:], size=9.0)
            i += 1
            continue
        add_body_paragraph(doc, raw)
        i += 1

    # A trailing continuous section break lets Word balance the final page's
    # two columns, including the reference list.
    final_section = doc.add_section(WD_SECTION.CONTINUOUS)
    final_section.page_width = Inches(8.27)
    final_section.page_height = Inches(11.69)
    final_section.top_margin = Inches(0.68)
    final_section.bottom_margin = Inches(0.65)
    final_section.left_margin = Inches(0.68)
    final_section.right_margin = Inches(0.68)
    final_cols = final_section._sectPr.xpath("./w:cols")
    if final_cols:
        final_cols[0].set(qn("w:num"), "2")
        final_cols[0].set(qn("w:space"), "360")
        final_cols[0].set(qn("w:equalWidth"), "1")

    doc.core_properties.title = title
    doc.core_properties.author = "Sakshi Singh; Rushil Chaudhary; Zoya Parveen; Yashsvi Sharma"
    doc.core_properties.subject = "IEEE-style network anomaly detection research paper"
    doc.save(OUTPUT)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()

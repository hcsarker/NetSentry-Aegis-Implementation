"""
build_v3_docx.py
-----------------
Builds paper/NetSentry-Aegis_Research_Paper_v3_Revised.docx from
paper/NetSentry-Aegis_Research_Paper_Revised.md and the original
embedded media/drawing assets in paper/NetSentry-Aegis_Research_Paper_v2.docx.
Uses Python's standard library (zipfile + xml.etree.ElementTree).
"""

import os
import re
import xml.etree.ElementTree as ET
import zipfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DOCX = os.path.join(BASE_DIR, "NetSentry-Aegis_Research_Paper_v2.docx")
MD_FILE = os.path.join(BASE_DIR, "NetSentry-Aegis_Research_Paper_Revised.md")
OUT_DOCX = os.path.join(BASE_DIR, "NetSentry-Aegis_Research_Paper_v3_Revised.docx")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
ET.register_namespace("w", W_NS)
ET.register_namespace("r", "http://schemas.openxmlformats.org/officeDocument/2006/relationships")
ET.register_namespace("wp", "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing")
ET.register_namespace("a", "http://schemas.openxmlformats.org/drawingml/2006/main")
ET.register_namespace("pic", "http://schemas.openxmlformats.org/drawingml/2006/picture")


def make_elem(tag, **attribs):
    elem = ET.Element(f"{{{W_NS}}}{tag}")
    for k, v in attribs.items():
        elem.set(k if ":" in k else f"{{{W_NS}}}{k}", v)
    return elem


def make_text_run(text, bold=False, italic=False, font_size=None, font_name="Times New Roman", color=None):
    r = make_elem("r")
    rPr = make_elem("rPr")
    
    if font_name:
        rFonts = make_elem("rFonts")
        rFonts.set(f"{{{W_NS}}}ascii", font_name)
        rFonts.set(f"{{{W_NS}}}hAnsi", font_name)
        rPr.append(rFonts)
        
    if bold:
        rPr.append(make_elem("b"))
    if italic:
        rPr.append(make_elem("i"))
    if font_size:
        sz = make_elem("sz")
        sz.set(f"{{{W_NS}}}val", str(int(font_size * 2)))
        rPr.append(sz)
    if color:
        c = make_elem("color")
        c.set(f"{{{W_NS}}}val", color)
        rPr.append(c)
        
    r.append(rPr)
    t = make_elem("t")
    t.text = text
    t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    r.append(t)
    return r


def make_p(text=None, align="both", space_before=100, space_after=100, bold=False, italic=False, font_size=10.0, font_name="Times New Roman"):
    p = make_elem("p")
    pPr = make_elem("pPr")
    
    if align != "left":
        jc = make_elem("jc")
        jc.set(f"{{{W_NS}}}val", align)
        pPr.append(jc)
        
    sp = make_elem("spacing")
    sp.set(f"{{{W_NS}}}before", str(space_before))
    sp.set(f"{{{W_NS}}}after", str(space_after))
    sp.set(f"{{{W_NS}}}line", "240")
    sp.set(f"{{{W_NS}}}lineRule", "auto")
    pPr.append(sp)
    
    p.append(pPr)
    if text:
        # Check for bold/italic markdown spans
        p.append(make_text_run(text, bold=bold, italic=italic, font_size=font_size, font_name=font_name))
    return p


def make_formatted_paragraph(line, align="both", space_before=60, space_after=80):
    p = make_elem("p")
    pPr = make_elem("pPr")
    
    if align != "left":
        jc = make_elem("jc")
        jc.set(f"{{{W_NS}}}val", align)
        pPr.append(jc)
        
    sp = make_elem("spacing")
    sp.set(f"{{{W_NS}}}before", str(space_before))
    sp.set(f"{{{W_NS}}}after", str(space_after))
    pPr.append(sp)
    p.append(pPr)
    
    # Parse basic markdown formatting (**bold**, *italic*, `code`)
    tokens = re.split(r'(\*\*.*?\*\*|\*.*?\*|`.*?`)', line)
    for tok in tokens:
        if not tok:
            continue
        if tok.startswith("**") and tok.endswith("**"):
            p.append(make_text_run(tok[2:-2], bold=True, font_size=10.0))
        elif tok.startswith("*") and tok.endswith("*"):
            p.append(make_text_run(tok[1:-1], italic=True, font_size=10.0))
        elif tok.startswith("`") and tok.endswith("`"):
            p.append(make_text_run(tok[1:-1], font_name="Courier New", font_size=9.5))
        else:
            p.append(make_text_run(tok, font_size=10.0))
    return p


def make_table(headers, rows):
    tbl = make_elem("tbl")
    tblPr = make_elem("tblPr")
    
    tblW = make_elem("tblW")
    tblW.set(f"{{{W_NS}}}w", "5000")
    tblW.set(f"{{{W_NS}}}type", "pct")
    tblPr.append(tblW)
    
    tblBorders = make_elem("tblBorders")
    for b in ["top", "left", "bottom", "right", "insideH"]:
        border = make_elem(b)
        border.set(f"{{{W_NS}}}val", "single")
        border.set(f"{{{W_NS}}}sz", "4")
        border.set(f"{{{W_NS}}}space", "0")
        border.set(f"{{{W_NS}}}color", "CCCCCC")
        tblBorders.append(border)
    tblPr.append(tblBorders)
    tbl.append(tblPr)
    
    # Header Row
    tr_h = make_elem("tr")
    trPr_h = make_elem("trPr")
    trPr_h.append(make_elem("tblHeader"))
    tr_h.append(trPr_h)
    
    for h in headers:
        tc = make_elem("tc")
        tcPr = make_elem("tcPr")
        shd = make_elem("shd")
        shd.set(f"{{{W_NS}}}val", "clear")
        shd.set(f"{{{W_NS}}}color", "auto")
        shd.set(f"{{{W_NS}}}fill", "F0F4F8")
        tcPr.append(shd)
        tc.append(tcPr)
        
        p = make_p(h.strip(), align="center", space_before=40, space_after=40, bold=True, font_size=9.0)
        tc.append(p)
        tr_h.append(tc)
    tbl.append(tr_h)
    
    # Data Rows
    for row_idx, row in enumerate(rows):
        tr = make_elem("tr")
        for cell_idx, c in enumerate(row):
            tc = make_elem("tc")
            p = make_elem("p")
            pPr = make_elem("pPr")
            sp = make_elem("spacing")
            sp.set(f"{{{W_NS}}}before", "30")
            sp.set(f"{{{W_NS}}}after", "30")
            pPr.append(sp)
            p.append(pPr)
            
            clean_c = c.strip()
            bold = ("**" in clean_c)
            text_val = clean_c.replace("**", "").replace("*", "")
            p.append(make_text_run(text_val, bold=bold, font_size=8.5))
            tc.append(p)
            tr.append(tc)
        tbl.append(tr)
        
    return tbl


def main():
    print(f"[*] Reading original docx template from: {SRC_DOCX}")
    with zipfile.ZipFile(SRC_DOCX, "r") as z_src:
        src_xml = z_src.read("word/document.xml")
        root_src = ET.fromstring(src_xml)
        
        # Extract sectPr
        ns = {"w": W_NS}
        sectPr = root_src.find(".//w:body/w:sectPr", ns)
        
        # Extract original drawings
        drawings = root_src.findall(".//w:drawing", ns)
        print(f"[+] Found {len(drawings)} drawing elements in original docx.")

    print(f"[*] Reading revised markdown from: {MD_FILE}")
    with open(MD_FILE, "r", encoding="utf-8") as f:
        md_text = f.read()

    lines = md_text.split("\n")
    
    # Create new document structure
    doc = make_elem("document")
    body = make_elem("body")
    doc.append(body)

    # Drawing index pointer for figures
    # Figures mapping:
    # 0: fig1_architecture, 1: fig2_pipeline, 2: fig4_model_comparison
    # 3: fig5_roc_curves, 4: fig6_confusion_matrices, 5: fig7_feature_importance
    # 6: fig8_latency_size, 7: fig9_trust_trajectories, 8: fig10_enforcement_summary
    # 9: fig11_cross_validation, 10: fig12_cicids_comparison, 11: fig13_adversarial_sweep
    fig_map = {
        "fig. 1": 0, "fig 1": 0,
        "fig. 2": 1, "fig 2": 1,
        "fig. 4": 2, "fig 4": 2,
        "fig. 5": 3, "fig 5": 3,
        "fig. 6": 4, "fig 6": 4,
        "fig. 7": 5, "fig 7": 5,
        "fig. 8": 6, "fig 8": 6,
        "fig. 9": 7, "fig 9": 7,
        "fig. 10": 8, "fig 10": 8,
        "fig. 11": 9, "fig 11": 9,
        "fig. 12": 10, "fig 12": 10,
        "fig. 13": 11, "fig 13": 11,
    }

    in_table = False
    table_headers = []
    table_rows = []
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Check if table row
        if line.startswith("|") and line.endswith("|"):
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if not in_table:
                in_table = True
                table_headers = cells
                table_rows = []
                i += 1
                # Skip separator row if present
                if i < len(lines) and "---" in lines[i]:
                    i += 1
                continue
            else:
                table_rows.append(cells)
                i += 1
                continue
        else:
            if in_table:
                # Flush table
                tbl = make_table(table_headers, table_rows)
                body.append(tbl)
                in_table = False
                table_headers = []
                table_rows = []

        if not line or line.startswith("```"):
            i += 1
            continue

        # Main Title
        if line.startswith("# "):
            title_text = line[2:].strip()
            p = make_p(title_text, align="center", space_before=240, space_after=180, bold=True, font_size=17.0, font_name="Times New Roman")
            body.append(p)
        # Authors
        elif line.startswith("**Authors:**"):
            p = make_p(line.replace("**", ""), align="center", space_before=60, space_after=120, italic=True, font_size=10.5)
            body.append(p)
        # Section Heading I, II, III
        elif line.startswith("## "):
            sec_text = line[3:].strip()
            p = make_p(sec_text, align="left", space_before=240, space_after=100, bold=True, font_size=12.0, font_name="Times New Roman")
            body.append(p)
        # Sub-heading A, B, C
        elif line.startswith("### "):
            subsec_text = line[4:].strip()
            p = make_p(subsec_text, align="left", space_before=160, space_after=80, bold=True, italic=True, font_size=11.0, font_name="Times New Roman")
            body.append(p)
        # Sub-sub-heading 1, 2
        elif line.startswith("#### "):
            subsubsec_text = line[5:].strip()
            p = make_p(subsubsec_text, align="left", space_before=120, space_after=60, bold=True, font_size=10.0, font_name="Times New Roman")
            body.append(p)
        # Check for Figure captions and insert matching drawing
        elif any(f_key in line.lower() for f_key in fig_map) and ("fig." in line.lower() or "fig " in line.lower()):
            matched_idx = None
            for f_key, d_idx in fig_map.items():
                if f_key in line.lower():
                    matched_idx = d_idx
                    break
            
            if matched_idx is not None and matched_idx < len(drawings):
                # Insert Drawing paragraph
                p_draw = make_elem("p")
                pPr_draw = make_elem("pPr")
                jc_draw = make_elem("jc")
                jc_draw.set(f"{{{W_NS}}}val", "center")
                pPr_draw.append(jc_draw)
                p_draw.append(pPr_draw)
                
                r_draw = make_elem("r")
                r_draw.append(drawings[matched_idx])
                p_draw.append(r_draw)
                body.append(p_draw)
                
            # Caption paragraph
            p_cap = make_p(line, align="center", space_before=60, space_after=140, italic=True, font_size=9.0)
            body.append(p_cap)
        # Bullet list item
        elif line.startswith("- "):
            p = make_formatted_paragraph(line[2:], align="both", space_before=30, space_after=40)
            pPr = p.find(f"{{{W_NS}}}pPr")
            ind = make_elem("ind")
            ind.set(f"{{{W_NS}}}left", "360")
            ind.set(f"{{{W_NS}}}hanging", "180")
            pPr.append(ind)
            body.append(p)
        # Math block
        elif line.startswith("$$") and line.endswith("$$"):
            math_text = line[2:-2].strip()
            p = make_p(math_text, align="center", space_before=80, space_after=80, italic=True, font_size=10.0, font_name="Cambria Math")
            body.append(p)
        # Normal prose paragraph
        else:
            p = make_formatted_paragraph(line, align="both", space_before=40, space_after=60)
            body.append(p)
            
        i += 1

    # End table if file ended inside table
    if in_table:
        tbl = make_table(table_headers, table_rows)
        body.append(tbl)

    # Append sectPr at end of body
    if sectPr is not None:
        body.append(sectPr)

    # Serialize new document.xml
    new_doc_xml = ET.tostring(doc, encoding="utf-8", xml_declaration=True)

    print(f"[*] Writing new package to: {OUT_DOCX}")
    with zipfile.ZipFile(SRC_DOCX, "r") as zin, zipfile.ZipFile(OUT_DOCX, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == "word/document.xml":
                zout.writestr("word/document.xml", new_doc_xml)
            else:
                zout.writestr(item, zin.read(item.filename))

    print(f"[SUCCESS] Created {OUT_DOCX} successfully!")


if __name__ == "__main__":
    main()


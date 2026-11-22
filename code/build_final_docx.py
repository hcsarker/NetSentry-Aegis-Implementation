import os
import re
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    tcPr.append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>'))

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tcPr.append(tcMar)

def create_publishable_docx(md_path, docx_out_path):
    print(f"Reading markdown from: {md_path}")
    with open(md_path, 'r', encoding='utf-8') as f:
        text = f.read()

    doc = docx.Document()

    # Set standard academic 1-inch margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Base styling
    normal_style = doc.styles['Normal']
    normal_font = normal_style.font
    normal_font.name = 'Times New Roman'
    normal_font.size = Pt(11)
    normal_font.color.rgb = RGBColor(0x22, 0x22, 0x22)

    lines = text.split('\n')
    i = 0
    in_table = False
    table_lines = []

    while i < len(lines):
        line = lines[i].strip()

        # Handle Tables
        if line.startswith('|') and line.endswith('|'):
            table_lines.append(line)
            i += 1
            continue
        elif table_lines:
            # Process accumulated table
            parse_and_add_table(doc, table_lines)
            table_lines = []

        if not line:
            i += 1
            continue

        # Skip horizontal rules
        if line in ['---', '***', '___']:
            i += 1
            continue

        # Title (# )
        if line.startswith('# '):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(12)
            run = p.add_run(line[2:].strip())
            run.font.name = 'Times New Roman'
            run.font.size = Pt(18)
            run.bold = True
            run.font.color.rgb = RGBColor(0x11, 0x22, 0x44)
            i += 1
            continue

        # Section Heading (## )
        if line.startswith('## '):
            heading_text = line[3:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(18)
            p.paragraph_format.space_after = Pt(6)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(heading_text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(13)
            run.bold = True
            run.font.color.rgb = RGBColor(0x1F, 0x4E, 0x8C)
            i += 1
            continue

        # Sub-heading (### )
        if line.startswith('### '):
            heading_text = line[4:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(heading_text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(11.5)
            run.bold = True
            run.font.color.rgb = RGBColor(0x0E, 0x7C, 0x7B)
            i += 1
            continue

        # Sub-sub-heading (#### )
        if line.startswith('#### '):
            heading_text = line[5:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(8)
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(heading_text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(11)
            run.bold = True
            run.italic = True
            i += 1
            continue

        # Code block (```)
        if line.startswith('```'):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            i += 1 # skip ending ```
            code_text = '\n'.join(code_lines)
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(6)
            p.paragraph_format.space_after = Pt(6)
            p.paragraph_format.left_indent = Inches(0.3)
            run = p.add_run(code_text)
            run.font.name = 'Consolas'
            run.font.size = Pt(8.5)
            run.font.color.rgb = RGBColor(0x22, 0x22, 0x33)
            continue

        # Bullet list
        if line.startswith('- ') or line.startswith('* '):
            p = doc.add_paragraph(style='List Bullet')
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.line_spacing = 1.15
            add_formatted_runs(p, line[2:].strip())
            i += 1
            continue

        # Numbered list
        m_num = re.match(r'^(\d+)\.\s+(.*)$', line)
        if m_num:
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.25)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.line_spacing = 1.15
            run_num = p.add_run(f"{m_num.group(1)}. ")
            run_num.bold = True
            run_num.font.name = 'Times New Roman'
            add_formatted_runs(p, m_num.group(2).strip())
            i += 1
            continue

        # Regular Paragraph
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.15
        
        # Center authors / metadata if near top
        if 'Authors:' in line or 'Department of' in line or 'Target Venue:' in line:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(line)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(10)
            if 'Authors:' in line:
                run.bold = True
            i += 1
            continue

        add_formatted_runs(p, line)
        i += 1

    # Check if table at the very end
    if table_lines:
        parse_and_add_table(doc, table_lines)

    # Embed relevant figures if available
    embed_figures(doc)

    print(f"Saving final formatted document to: {docx_out_path}")
    doc.save(docx_out_path)
    print("SUCCESS: Full DOCX Generated!")

def add_formatted_runs(paragraph, text):
    """Parses bold **text**, italic *text*, math $math$, and code `code`"""
    # Regex pattern to match formatted tokens
    pattern = re.compile(r'(\*\*.*?\*\*|\*.*?\*|`.*?`|\$.*?\$|\[.*?\]\(.*?\))')
    parts = pattern.split(text)

    for part in parts:
        if not part:
            continue
        if part.startswith('**') and part.endswith('**') and len(part) >= 4:
            r = paragraph.add_run(part[2:-2])
            r.bold = True
            r.font.name = 'Times New Roman'
        elif part.startswith('*') and part.endswith('*') and len(part) >= 2:
            r = paragraph.add_run(part[1:-1])
            r.italic = True
            r.font.name = 'Times New Roman'
        elif part.startswith('`') and part.endswith('`') and len(part) >= 2:
            r = paragraph.add_run(part[1:-1])
            r.font.name = 'Consolas'
            r.font.size = Pt(9.5)
            r.font.color.rgb = RGBColor(0x8B, 0x1A, 0x1A)
        elif part.startswith('$') and part.endswith('$') and len(part) >= 2:
            # Inline math
            r = paragraph.add_run(part[1:-1])
            r.italic = True
            r.font.name = 'Cambria Math'
        elif part.startswith('[') and '](' in part:
            m = re.match(r'\[(.*?)\]\((.*?)\)', part)
            if m:
                r = paragraph.add_run(m.group(1))
                r.font.name = 'Times New Roman'
                r.font.color.rgb = RGBColor(0x1F, 0x4E, 0x8C)
                r.underline = True
        else:
            r = paragraph.add_run(part)
            r.font.name = 'Times New Roman'

def parse_and_add_table(doc, table_lines):
    clean_lines = [l for l in table_lines if not re.match(r'^\|?\s*[-:]+[-| :]*$', l)]
    if not clean_lines:
        return

    rows = []
    for l in clean_lines:
        cells = [c.strip() for c in l.strip('|').split('|')]
        rows.append(cells)

    if not rows:
        return

    col_count = max(len(r) for r in rows)
    table = doc.add_table(rows=len(rows), cols=col_count)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    # Format table borders and cells
    for r_idx, row_data in enumerate(rows):
        is_header = (r_idx == 0)
        row = table.rows[r_idx]
        
        # CantSplit row across pages
        trPr = row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))

        for c_idx in range(col_count):
            cell = row.cells[c_idx]
            text = row_data[c_idx] if c_idx < len(row_data) else ""
            
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(3)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.line_spacing = 1.05
            
            add_formatted_runs(p, text)
            
            if is_header:
                set_cell_background(cell, "1F4E8C")
                for r in p.runs:
                    r.font.bold = True
                    r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                    r.font.name = 'Times New Roman'
                    r.font.size = Pt(9.5)
            else:
                bg = "F4F6F9" if r_idx % 2 == 1 else "FFFFFF"
                set_cell_background(cell, bg)
                for r in p.runs:
                    r.font.name = 'Times New Roman'
                    r.font.size = Pt(9)
            
            set_cell_margins(cell, top=80, bottom=80, left=120, right=120)

    p_after = doc.add_paragraph()
    p_after.paragraph_format.space_before = Pt(0)
    p_after.paragraph_format.space_after = Pt(6)

def embed_figures(doc):
    fig_map = [
        ("Figure 1: NetSentry-Aegis Layered Edge Architecture", "figs/fig1_architecture.png"),
        ("Figure 2: End-to-End Zero-Trust Verification Pipeline", "figs/fig2_pipeline.png"),
        ("Figure 4: Candidate Detector Performance Comparison", "figs/fig4_model_comparison.png"),
        ("Figure 5: Receiver Operating Characteristic (ROC) Curves", "figs/fig5_roc_curves.png"),
        ("Figure 7: Top 15 Feature Importances by Gini Impurity", "figs/fig7_feature_importance.png"),
        ("Figure 8: Latency vs. Serialized Memory Footprint Trade-off", "figs/fig8_latency_size.png"),
        ("Figure 9: Continuous Dynamic Trust-Score Trajectories", "figs/fig9_trust_trajectories.png"),
        ("Figure 10: Multi-Regime Enforcement Effectiveness", "figs/fig10_enforcement_summary.png"),
        ("Figure 11: Stratified 5-Fold Cross-Validation Performance", "figs/fig11_cross_validation.png"),
        ("Figure 13: Black-Box Adversarial Evasion Sweep", "figs/fig13_adversarial_sweep.png"),
        ("Figure 14: Cross-Benchmark Generalization Across 5 Network & IoT Datasets", "figs/fig14_multi_dataset_comparison.png")
    ]

    p_div = doc.add_paragraph()
    p_div.paragraph_format.space_before = Pt(18)
    p_div.paragraph_format.space_after = Pt(6)
    r_div = p_div.add_run("--- APPENDIX: EMBEDDED SYSTEM DIAGRAMS AND EMPIRICAL FIGURES ---")
    r_div.bold = True
    r_div.font.size = Pt(12)
    r_div.font.color.rgb = RGBColor(0x1F, 0x4E, 0x8C)

    for caption, path in fig_map:
        if os.path.exists(path):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.keep_with_next = True
            try:
                run = p.add_run()
                run.add_picture(path, width=Inches(5.8))
                
                p_cap = doc.add_paragraph()
                p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p_cap.paragraph_format.space_before = Pt(2)
                p_cap.paragraph_format.space_after = Pt(14)
                r_cap = p_cap.add_run(caption)
                r_cap.font.name = 'Times New Roman'
                r_cap.font.size = Pt(9.5)
                r_cap.italic = True
                r_cap.font.color.rgb = RGBColor(0x44, 0x44, 0x44)
            except Exception as e:
                print(f"Notice: Could not insert picture {path}: {e}")

if __name__ == '__main__':
    md = 'paper/NetSentry-Aegis_FINAL_Publishable_Manuscript.md'
    out = 'paper/NetSentry-Aegis_Journal_Manuscript_Final.docx'
    create_publishable_docx(md, out)

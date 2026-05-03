"""Generate a professional multi-page PDF report summarizing findings."""
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable
)
from reportlab.lib import colors
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Color palette
DARK_BG = HexColor('#0f1117')
ACCENT_CYAN = HexColor('#00CFC1')
ACCENT_RED = HexColor('#E8364F')
ACCENT_YELLOW = HexColor('#E8A817')
ACCENT_GREEN = HexColor('#17B978')
ACCENT_BLUE = HexColor('#2E86DE')
TEXT_WHITE = HexColor('#E6EDF3')
TEXT_GRAY = HexColor('#8B949E')
HEADER_BG = HexColor('#161B22')
ROW_ALT = HexColor('#1C2333')
ROW_NORMAL = HexColor('#0D1117')
BORDER_COLOR = HexColor('#30363D')


def _build_styles():
    """Create all paragraph styles used in the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        'CoverTitle', fontName='Helvetica-Bold', fontSize=28,
        textColor=ACCENT_CYAN, alignment=TA_CENTER, spaceAfter=12))

    styles.add(ParagraphStyle(
        'CoverSub', fontName='Helvetica', fontSize=13,
        textColor=TEXT_GRAY, alignment=TA_CENTER, spaceAfter=6))

    styles.add(ParagraphStyle(
        'SectionTitle', fontName='Helvetica-Bold', fontSize=16,
        textColor=ACCENT_CYAN, spaceBefore=24, spaceAfter=10,
        borderPadding=(0, 0, 4, 0)))

    styles.add(ParagraphStyle(
        'SubSection', fontName='Helvetica-Bold', fontSize=12,
        textColor=TEXT_WHITE, spaceBefore=14, spaceAfter=6))

    styles.add(ParagraphStyle(
        'BodyText2', fontName='Helvetica', fontSize=10,
        textColor=TEXT_WHITE, leading=15, alignment=TA_JUSTIFY,
        spaceAfter=6))

    styles.add(ParagraphStyle(
        'SmallGray', fontName='Helvetica', fontSize=8,
        textColor=TEXT_GRAY, alignment=TA_CENTER))

    styles.add(ParagraphStyle(
        'BulletItem', fontName='Helvetica', fontSize=10,
        textColor=TEXT_WHITE, leading=15, leftIndent=20,
        bulletIndent=8, spaceAfter=4))

    return styles


def _severity_color(confidence):
    if confidence >= 0.8:
        return ACCENT_RED
    if confidence >= 0.5:
        return ACCENT_YELLOW
    return ACCENT_GREEN


def _severity_label(confidence):
    if confidence >= 0.8:
        return 'CRITICAL'
    if confidence >= 0.5:
        return 'HIGH'
    return 'MEDIUM'


def _header_footer(canvas_obj, doc):
    """Draw dark background, header line, and footer on every page."""
    w, h = letter
    # Dark background
    canvas_obj.setFillColor(DARK_BG)
    canvas_obj.rect(0, 0, w, h, fill=1, stroke=0)
    # Header accent line
    canvas_obj.setStrokeColor(ACCENT_CYAN)
    canvas_obj.setLineWidth(2)
    canvas_obj.line(40, h - 40, w - 40, h - 40)
    # Header text
    canvas_obj.setFont('Helvetica-Bold', 8)
    canvas_obj.setFillColor(ACCENT_CYAN)
    canvas_obj.drawString(40, h - 34, 'CYBER ATTACK PATH ANALYZER')
    canvas_obj.setFillColor(TEXT_GRAY)
    canvas_obj.setFont('Helvetica', 8)
    canvas_obj.drawRightString(w - 40, h - 34, 'CONFIDENTIAL')
    # Footer
    canvas_obj.setStrokeColor(BORDER_COLOR)
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(40, 36, w - 40, 36)
    canvas_obj.setFont('Helvetica', 7)
    canvas_obj.setFillColor(TEXT_GRAY)
    canvas_obj.drawString(40, 24, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    canvas_obj.drawRightString(w - 40, 24, f'Page {doc.page}')


class ReportGenerator:
    """Create a professional multi-page PDF report."""

    def generate(self, root_causes, recommendations, output_path,
                 events=None, graph_image_path=None, mitre_mappings=None,
                 scan_results=None, movements=None):
        """Build and save the PDF report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        styles = _build_styles()

        doc = SimpleDocTemplate(
            output_path, pagesize=letter,
            topMargin=60, bottomMargin=50,
            leftMargin=50, rightMargin=50)

        story = []

        # ── COVER PAGE ──
        story.append(Spacer(1, 2.2 * inch))
        story.append(Paragraph('CYBER ATTACK PATH', styles['CoverTitle']))
        story.append(Paragraph('ANALYSIS REPORT', styles['CoverTitle']))
        story.append(Spacer(1, 0.3 * inch))
        story.append(HRFlowable(
            width='60%', thickness=2, color=ACCENT_CYAN,
            spaceAfter=16, spaceBefore=0, hAlign='CENTER'))
        story.append(Paragraph(
            'AI-Powered Threat Intelligence and Root Cause Analysis',
            styles['CoverSub']))
        story.append(Paragraph(
            f'Report Date: {datetime.now().strftime("%B %d, %Y  |  %H:%M")}',
            styles['CoverSub']))
        story.append(Paragraph('Classification: Confidential', styles['CoverSub']))
        story.append(Spacer(1, 1.5 * inch))
        story.append(Paragraph(
            'This report was generated automatically by the Cyber Attack Path Analyzer '
            'framework using machine-learning-based root cause analysis.',
            styles['SmallGray']))
        story.append(PageBreak())

        # ── TABLE OF CONTENTS ──
        story.append(Paragraph('TABLE OF CONTENTS', styles['SectionTitle']))
        story.append(Spacer(1, 10))
        toc_items = [
            '1. Executive Summary',
            '2. Root Cause Analysis',
            '3. Threat Severity Matrix',
            '4. Remediation Recommendations',
            '5. Security Event Log',
            '6. Attack Path Visualization',
            '7. MITRE ATT&CK Mapping',
        ]
        for item in toc_items:
            story.append(Paragraph(item, styles['BodyText2']))
        story.append(PageBreak())

        # ── 1. EXECUTIVE SUMMARY ──
        story.append(Paragraph('1. EXECUTIVE SUMMARY', styles['SectionTitle']))
        story.append(HRFlowable(width='100%', thickness=1, color=BORDER_COLOR, spaceAfter=12))

        total_events = len(events) if events else 0
        threat_count = len([c for c in root_causes if 'Normal' not in c.get('cause', '')])
        max_conf = max((c.get('confidence', 0) for c in root_causes), default=0)
        overall_sev = _severity_label(max_conf)

        story.append(Paragraph(
            f'The automated simulation identified <b>{threat_count}</b> distinct threat '
            f'categories across <b>{total_events}</b> logged security events. '
            f'The overall risk assessment is rated as '
            f'<font color="#{_severity_color(max_conf).hexval()[2:]}">'
            f'<b>{overall_sev}</b></font>.',
            styles['BodyText2']))
        story.append(Spacer(1, 8))

        # Summary stats table
        summary_data = [
            ['Metric', 'Value'],
            ['Total Security Events', str(total_events)],
            ['Threat Categories Identified', str(threat_count)],
            ['Recommendations Generated', str(len(recommendations))],
            ['Overall Risk Rating', overall_sev],
            ['ML Model', 'RandomForest Classifier'],
            ['Analysis Timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]
        t = Table(summary_data, colWidths=[3.2 * inch, 3.2 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ACCENT_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), DARK_BG),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), HEADER_BG),
            ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_WHITE),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HEADER_BG, ROW_ALT]),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(t)
        story.append(PageBreak())

        # ── 2. ROOT CAUSE ANALYSIS ──
        story.append(Paragraph('2. ROOT CAUSE ANALYSIS', styles['SectionTitle']))
        story.append(HRFlowable(width='100%', thickness=1, color=BORDER_COLOR, spaceAfter=12))
        story.append(Paragraph(
            'The following root causes were identified by the trained Random Forest '
            'classifier. Each cause includes a confidence score derived from the '
            'model prediction probabilities.',
            styles['BodyText2']))
        story.append(Spacer(1, 8))

        rc_data = [['Root Cause', 'Confidence', 'Severity']]
        for cause in root_causes:
            conf = cause.get('confidence', 0)
            sev = _severity_label(conf)
            rc_data.append([
                cause.get('cause', 'Unknown'),
                f'{conf:.0%}',
                sev
            ])

        t2 = Table(rc_data, colWidths=[3.2 * inch, 1.5 * inch, 1.7 * inch])
        sev_colors = {
            'CRITICAL': ACCENT_RED, 'HIGH': ACCENT_YELLOW, 'MEDIUM': ACCENT_GREEN
        }
        base_style = [
            ('BACKGROUND', (0, 0), (-1, 0), ACCENT_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), DARK_BG),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), HEADER_BG),
            ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_WHITE),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HEADER_BG, ROW_ALT]),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 1), (2, -1), 'CENTER'),
        ]
        for idx, cause in enumerate(root_causes, start=1):
            sev = _severity_label(cause.get('confidence', 0))
            c = sev_colors.get(sev, TEXT_WHITE)
            base_style.append(('TEXTCOLOR', (2, idx), (2, idx), c))
            base_style.append(('FONTNAME', (2, idx), (2, idx), 'Helvetica-Bold'))

        t2.setStyle(TableStyle(base_style))
        story.append(t2)

        # Detailed breakdown
        story.append(Spacer(1, 14))
        story.append(Paragraph('Detailed Breakdown', styles['SubSection']))
        for i, cause in enumerate(root_causes, 1):
            conf = cause.get('confidence', 0)
            sev = _severity_label(conf)
            col = _severity_color(conf).hexval()[2:]
            name = cause.get('cause', 'Unknown')
            story.append(Paragraph(
                f'<b>{i}. {name}</b>  '
                f'<font color="#{col}">[{sev}]</font>  '
                f'Confidence: {conf:.0%}',
                styles['BulletItem']))
            desc_map = {
                'credential brute force': (
                    'Multiple failed authentication attempts detected from external sources. '
                    'This pattern indicates a systematic credential guessing attack targeting '
                    'SSH and remote management services.'),
                'privilege escalation': (
                    'Unauthorized attempts to elevate process privileges were identified. '
                    'An attacker may be exploiting kernel or service-level vulnerabilities '
                    'to gain root/administrator access.'),
                'lateral movement': (
                    'Compromised credentials were used to pivot across network segments. '
                    'The attacker moved from initially compromised hosts to adjacent systems '
                    'using legitimate remote access protocols.'),
                'scanning': (
                    'Reconnaissance activity detected including TCP port scans and service '
                    'enumeration. This is typically the first phase of an intrusion attempt.'),
            }
            for key, desc in desc_map.items():
                if key in name.lower():
                    story.append(Paragraph(desc, styles['BodyText2']))
                    break

        story.append(PageBreak())

        # ── 3. THREAT SEVERITY MATRIX ──
        story.append(Paragraph('3. THREAT SEVERITY MATRIX', styles['SectionTitle']))
        story.append(HRFlowable(width='100%', thickness=1, color=BORDER_COLOR, spaceAfter=12))

        matrix_data = [['Severity', 'Confidence Range', 'Action Required', 'Count']]
        crit = len([c for c in root_causes if c.get('confidence', 0) >= 0.8 and 'Normal' not in c.get('cause', '')])
        high = len([c for c in root_causes if 0.5 <= c.get('confidence', 0) < 0.8 and 'Normal' not in c.get('cause', '')])
        med = len([c for c in root_causes if c.get('confidence', 0) < 0.5 and 'Normal' not in c.get('cause', '')])
        matrix_data.append(['CRITICAL', '80% - 100%', 'Immediate Response Required', str(crit)])
        matrix_data.append(['HIGH', '50% - 79%', 'Investigate Within 24 Hours', str(high)])
        matrix_data.append(['MEDIUM', 'Below 50%', 'Schedule Review', str(med)])

        t3 = Table(matrix_data, colWidths=[1.3*inch, 1.5*inch, 2.4*inch, 1.2*inch])
        t3.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ACCENT_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), DARK_BG),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), HEADER_BG),
            ('TEXTCOLOR', (0, 1), (0, 1), ACCENT_RED),
            ('TEXTCOLOR', (0, 2), (0, 2), ACCENT_YELLOW),
            ('TEXTCOLOR', (0, 3), (0, 3), ACCENT_GREEN),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (1, 1), (-1, -1), TEXT_WHITE),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
        ]))
        story.append(t3)
        story.append(PageBreak())

        # ── 4. REMEDIATION RECOMMENDATIONS ──
        story.append(Paragraph('4. REMEDIATION RECOMMENDATIONS', styles['SectionTitle']))
        story.append(HRFlowable(width='100%', thickness=1, color=BORDER_COLOR, spaceAfter=12))
        story.append(Paragraph(
            'The following actions are recommended based on the identified root causes. '
            'Items are ordered by priority.',
            styles['BodyText2']))
        story.append(Spacer(1, 6))

        for idx, rec in enumerate(recommendations, 1):
            priority = 'HIGH' if idx <= 3 else 'MEDIUM'
            col = ACCENT_RED.hexval()[2:] if priority == 'HIGH' else ACCENT_YELLOW.hexval()[2:]
            story.append(Paragraph(
                f'<font color="#{col}"><b>[{priority}]</b></font>  '
                f'<b>{idx}.</b>  {rec}',
                styles['BulletItem']))
        story.append(Spacer(1, 6))

        # ── 5. SECURITY EVENT LOG ──
        if events:
            story.append(PageBreak())
            story.append(Paragraph('5. SECURITY EVENT LOG', styles['SectionTitle']))
            story.append(HRFlowable(width='100%', thickness=1, color=BORDER_COLOR, spaceAfter=12))
            story.append(Paragraph(
                f'Showing the last {min(len(events), 25)} of {len(events)} events captured during the simulation.',
                styles['BodyText2']))
            story.append(Spacer(1, 6))

            ev_data = [['Time', 'Level', 'Source', 'Dest', 'Message']]
            for ev in events[-25:]:
                ts = ev.get('timestamp', '')
                if hasattr(ts, 'strftime'):
                    ts = ts.strftime('%H:%M:%S')
                else:
                    ts = str(ts)[-8:] if len(str(ts)) > 8 else str(ts)
                ev_data.append([
                    ts,
                    ev.get('level', 'INFO'),
                    ev.get('source_ip', '-') or '-',
                    ev.get('dest_ip', '-') or '-',
                    str(ev.get('message', ''))[:55]
                ])

            t4 = Table(ev_data, colWidths=[0.7*inch, 0.7*inch, 1.1*inch, 1.1*inch, 2.8*inch])
            ev_style = [
                ('BACKGROUND', (0, 0), (-1, 0), ACCENT_CYAN),
                ('TEXTCOLOR', (0, 0), (-1, 0), DARK_BG),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                ('BACKGROUND', (0, 1), (-1, -1), HEADER_BG),
                ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_WHITE),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HEADER_BG, ROW_ALT]),
                ('GRID', (0, 0), (-1, -1), 0.3, BORDER_COLOR),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ]
            for row_idx in range(1, len(ev_data)):
                lvl = ev_data[row_idx][1]
                if lvl == 'ERROR':
                    ev_style.append(('TEXTCOLOR', (1, row_idx), (1, row_idx), ACCENT_RED))
                elif lvl == 'WARNING':
                    ev_style.append(('TEXTCOLOR', (1, row_idx), (1, row_idx), ACCENT_YELLOW))
                else:
                    ev_style.append(('TEXTCOLOR', (1, row_idx), (1, row_idx), ACCENT_BLUE))
            t4.setStyle(TableStyle(ev_style))
            story.append(t4)

        # ── 6. ATTACK PATH VISUALIZATION ──
        if graph_image_path and os.path.exists(graph_image_path):
            story.append(PageBreak())
            story.append(Paragraph('6. ATTACK PATH VISUALIZATION', styles['SectionTitle']))
            story.append(HRFlowable(width='100%', thickness=1, color=BORDER_COLOR, spaceAfter=12))
            story.append(Paragraph(
                'The directed graph below illustrates the attack propagation path '
                'across the network topology.',
                styles['BodyText2']))
            story.append(Spacer(1, 10))
            try:
                img = Image(graph_image_path, width=5.5*inch, height=3.6*inch)
                story.append(img)
            except Exception as e:
                story.append(Paragraph(f'[Image could not be loaded: {e}]', styles['BodyText2']))

        # ── 7. MITRE ATT&CK MAPPING ──
        story.append(PageBreak())
        story.append(Paragraph('7. MITRE ATT&CK MAPPING', styles['SectionTitle']))
        story.append(HRFlowable(width='100%', thickness=1, color=BORDER_COLOR, spaceAfter=12))

        mitre_data = [['Technique', 'MITRE ID', 'Tactic', 'Description']]
        mitre_rows = [
            ['Port Scanning', 'T1046', 'Discovery', 'Active scanning of network ports to identify services'],
            ['Brute Force', 'T1110', 'Credential Access', 'Systematic password guessing against authentication services'],
            ['Exploitation for Privilege Escalation', 'T1068', 'Privilege Escalation', 'Exploiting software vulnerabilities to elevate access'],
            ['Remote Services', 'T1021', 'Lateral Movement', 'Using valid credentials to access remote network services'],
        ]
        if mitre_mappings:
            for step, tid in mitre_mappings.items():
                mitre_rows.append([step, tid, 'Lateral Movement', 'Mapped during simulation'])
        mitre_data.extend(mitre_rows)

        t5 = Table(mitre_data, colWidths=[1.8*inch, 0.8*inch, 1.4*inch, 2.4*inch])
        t5.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ACCENT_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), DARK_BG),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HEADER_BG),
            ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_WHITE),
            ('TEXTCOLOR', (1, 1), (1, -1), ACCENT_CYAN),
            ('FONTNAME', (1, 1), (1, -1), 'Courier-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HEADER_BG, ROW_ALT]),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t5)

        # ── END PAGE ──
        story.append(PageBreak())
        story.append(Spacer(1, 2.5 * inch))
        story.append(Paragraph('--- END OF REPORT ---', styles['CoverSub']))
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph(
            'This report was generated by the Cyber Attack Path Analyzer framework. '
            'All findings are based on simulated attack data processed through a '
            'machine learning classification pipeline.',
            styles['SmallGray']))

        # Build PDF
        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
        logger.info(f"Report saved to {output_path}")
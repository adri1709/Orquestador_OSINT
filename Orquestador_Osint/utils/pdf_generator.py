from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from datetime import datetime

def generate_osint_pdf(data, output_path):
    """Genera un PDF formateado con los resultados OSINT"""
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            rightMargin=50, leftMargin=50,
                            topMargin=50, bottomMargin=30)
    
    # Estilos con mejor contraste
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=26,
        textColor=colors.HexColor('#00aa44'),
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#00aa44'),
        spaceAfter=10,
        spaceBefore=15,
        fontName='Helvetica-Bold'
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#008833'),
        spaceAfter=8,
        spaceBefore=8,
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.black
    )
    
    # Contenido
    story = []
    
    # Título
    story.append(Paragraph("REPORTE OSINT", title_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Target
    if data.get('target'):
        story.append(Paragraph("Objetivo del Análisis", heading_style))
        target_data = []
        for key, value in data['target'].items():
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value[:3])
            target_data.append([
                Paragraph(f"<b>{key.upper()}:</b>", normal_style),
                Paragraph(str(value), normal_style)
            ])
        
        if target_data:
            t = Table(target_data, colWidths=[1.5*inch, 5*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#e8f5e9')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                ('ALIGN', (1, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#00aa44')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(t)
            story.append(Spacer(1, 0.3*inch))
    
    # Resultados
    if data.get('results'):
        story.append(Paragraph("Resultados del Análisis", heading_style))
        
        for result in data['results']:
            module_name = result.get('module', 'Unknown')
            story.append(Paragraph(f"{module_name.upper().replace('_', ' ')}", subheading_style))
            
            # WHOIS
            if module_name == 'whois' and result.get('result'):
                res = result['result']
                whois_data = []
                
                fields = [
                    ('domain_name', 'Dominio'),
                    ('registrar', 'Registrador'),
                    ('org', 'Organización'),
                    ('country', 'País'),
                    ('creation_date', 'Fecha Creación'),
                    ('expiration_date', 'Fecha Expiración'),
                    ('updated_date', 'Última Actualización'),
                    ('dnssec', 'DNSSEC'),
                    ('registrar_abuse_email', 'Email de Abuso')
                ]
                
                for field, label in fields:
                    if field in res and res[field]:
                        value = res[field]
                        if isinstance(value, list):
                            value = '<br/>'.join(str(v) for v in value[:3])
                        whois_data.append([
                            Paragraph(f"<b>{label}:</b>", normal_style),
                            Paragraph(str(value), normal_style)
                        ])
                
                # Nameservers
                if res.get('name_servers'):
                    ns_list = '<br/>'.join(res['name_servers'][:4])
                    whois_data.append([
                        Paragraph("<b>Nameservers:</b>", normal_style),
                        Paragraph(ns_list, normal_style)
                    ])
                
                if whois_data:
                    t = Table(whois_data, colWidths=[1.8*inch, 4.7*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f8f4')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                        ('ALIGN', (1, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTNAME', (1, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('PADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8e6c9')),
                        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8e6c9'))
                    ]))
                    story.append(t)
            
            # DNS
            elif module_name == 'dns' and result.get('records'):
                dns_data = []
                for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                    values = result['records'].get(record_type)
                    if not values:
                        continue
                    if isinstance(values, dict) and 'error' in values:
                        continue
                    if isinstance(values, list):
                        display_values = '<br/>'.join(str(v) for v in values[:5])
                        if len(values) > 5:
                            display_values += f'<br/><i>...y {len(values)-5} más</i>'
                        dns_data.append([
                            Paragraph(f"<b>{record_type}:</b>", normal_style),
                            Paragraph(display_values, normal_style)
                        ])
                
                if dns_data:
                    t = Table(dns_data, colWidths=[1*inch, 5.5*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f8f4')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                        ('ALIGN', (1, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTNAME', (1, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('PADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8e6c9'))
                    ]))
                    story.append(t)
            
            # HTTP Meta
            elif module_name == 'http_meta':
                if result.get('error'):
                    error_para = Paragraph(f"<i>⚠ {result['error']}</i>", 
                                          ParagraphStyle('error', parent=normal_style, textColor=colors.HexColor('#cc0000')))
                    story.append(error_para)
                else:
                    http_data = []
                    if result.get('title'):
                        http_data.append([Paragraph("<b>Título:</b>", normal_style), Paragraph(result['title'], normal_style)])
                    if result.get('final_url'):
                        http_data.append([Paragraph("<b>URL:</b>", normal_style), Paragraph(result['final_url'], normal_style)])
                    if http_data:
                        t = Table(http_data, colWidths=[1.5*inch, 5*inch])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f8f4')),
                            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('PADDING', (0, 0), (-1, -1), 8),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8e6c9'))
                        ]))
                        story.append(t)
            
            # Username
            elif module_name == 'username_check' and result.get('sites'):
                found = [s for s in result['sites'] if s.get('exists')]
                if found:
                    story.append(Paragraph(f"<b>Encontrado en {len(found)} sitios:</b>", normal_style))
                    for site in found[:10]:
                        story.append(Paragraph(f"  • {site['url']}", normal_style))
            
            # Phone
            elif module_name == 'phone_lookup' and result.get('result'):
                phone_data = []
                res = result['result']
                for key in ['valid', 'number', 'country_name', 'location', 'carrier', 'line_type']:
                    if key in res:
                        phone_data.append([
                            Paragraph(f"<b>{key.replace('_', ' ').title()}:</b>", normal_style),
                            Paragraph(str(res[key]), normal_style)
                        ])
                if phone_data:
                    t = Table(phone_data, colWidths=[1.8*inch, 4.7*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f8f4')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('PADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8e6c9'))
                    ]))
                    story.append(t)
            
            # Shodan
            elif module_name == 'shodan_host' and result.get('result'):
                res = result['result']
                shodan_data = []
                
                fields = [
                    ('ip', 'IP Address'),
                    ('organization', 'Organización'),
                    ('isp', 'ISP'),
                    ('country', 'País'),
                    ('city', 'Ciudad'),
                    ('asn', 'ASN'),
                    ('total_services', 'Servicios Detectados')
                ]
                
                for field, label in fields:
                    if field in res and res[field]:
                        shodan_data.append([
                            Paragraph(f"<b>{label}:</b>", normal_style),
                            Paragraph(str(res[field]), normal_style)
                        ])
                
                if res.get('hostnames'):
                    shodan_data.append([
                        Paragraph("<b>Hostnames:</b>", normal_style),
                        Paragraph('<br/>'.join(res['hostnames'][:3]), normal_style)
                    ])
                
                if res.get('ports'):
                    ports_str = ', '.join(map(str, res['ports'][:10]))
                    if len(res['ports']) > 10:
                        ports_str += f" (+{len(res['ports'])-10} más)"
                    shodan_data.append([
                        Paragraph("<b>Puertos Abiertos:</b>", normal_style),
                        Paragraph(ports_str, normal_style)
                    ])
                
                if res.get('vulns'):
                    vuln_style = ParagraphStyle('vuln', parent=normal_style, textColor=colors.HexColor('#cc0000'))
                    shodan_data.append([
                        Paragraph("<b>⚠️ Vulnerabilidades:</b>", vuln_style),
                        Paragraph('<br/>'.join(res['vulns'][:5]), vuln_style)
                    ])
                
                if shodan_data:
                    t = Table(shodan_data, colWidths=[1.8*inch, 4.7*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f8f4')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('PADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8e6c9'))
                    ]))
                    story.append(t)
                
                # Servicios detectados
                if res.get('services'):
                    story.append(Spacer(1, 0.1*inch))
                    story.append(Paragraph("<b>Servicios Detectados:</b>", normal_style))
                    for svc in res['services'][:3]:
                        story.append(Paragraph(
                            f"• Puerto {svc['port']}/{svc.get('transport', 'tcp')}: {svc.get('product', 'Unknown')} {svc.get('version', '')}",
                            normal_style
                        ))
            
            # EXIF
            elif module_name == 'exif_metadata' and result.get('results'):
                for img_result in result['results']:
                    if img_result.get('status') == 'success' and img_result.get('metadata'):
                        meta = img_result['metadata']
                        file_info = meta.get('file_info', {})
                        exif_data = meta.get('exif', {})
                        gps_data = meta.get('gps')
                        
                        # Tabla de información del archivo
                        img_data = []
                        img_data.append([
                            Paragraph("<b>Archivo:</b>", normal_style),
                            Paragraph(file_info.get('filename', 'N/A'), normal_style)
                        ])
                        img_data.append([
                            Paragraph("<b>Formato:</b>", normal_style),
                            Paragraph(f"{file_info.get('format', 'N/A')} | {file_info.get('mode', 'N/A')}", normal_style)
                        ])
                        img_data.append([
                            Paragraph("<b>Dimensiones:</b>", normal_style),
                            Paragraph(file_info.get('size_pixels', 'N/A'), normal_style)
                        ])
                        img_data.append([
                            Paragraph("<b>Tamaño:</b>", normal_style),
                            Paragraph(f"{file_info.get('file_size_bytes', 0):,} bytes ({file_info.get('file_size_bytes', 0) / 1024:.1f} KB)", normal_style)
                        ])
                        
                        # Información EXIF relevante
                        if exif_data:
                            if 'DateTimeOriginal' in exif_data:
                                img_data.append([
                                    Paragraph("<b>Fecha Original:</b>", normal_style),
                                    Paragraph(exif_data['DateTimeOriginal'], normal_style)
                                ])
                            if 'Software' in exif_data:
                                img_data.append([
                                    Paragraph("<b>Software:</b>", normal_style),
                                    Paragraph(exif_data['Software'], normal_style)
                                ])
                            if 'Make' in exif_data:
                                camera = exif_data.get('Make', '')
                                if 'Model' in exif_data:
                                    camera += f" {exif_data['Model']}"
                                img_data.append([
                                    Paragraph("<b>Cámara:</b>", normal_style),
                                    Paragraph(camera, normal_style)
                                ])
                        
                        # GPS Info
                        if gps_data and ('Latitude_Decimal' in gps_data or 'Longitude_Decimal' in gps_data):
                            lat = gps_data.get('Latitude_Decimal', 'N/A')
                            lon = gps_data.get('Longitude_Decimal', 'N/A')
                            img_data.append([
                                Paragraph("<b>📍 GPS:</b>", ParagraphStyle('gps', parent=normal_style, textColor=colors.HexColor('#cc0000'))),
                                Paragraph(f"<b>{lat}, {lon}</b><br/>(Ver en Google Maps)", 
                                         ParagraphStyle('gps_val', parent=normal_style, textColor=colors.HexColor('#cc0000')))
                            ])
                        else:
                            img_data.append([
                                Paragraph("<b>📍 GPS:</b>", normal_style),
                                Paragraph("<i>No disponible</i>", normal_style)
                            ])
                        
                        # Crear tabla
                        t = Table(img_data, colWidths=[1.5*inch, 5*inch])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f8f4')),
                            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                            ('ALIGN', (1, 0), (-1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTNAME', (1, 0), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('PADDING', (0, 0), (-1, -1), 8),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8e6c9'))
                        ]))
                        story.append(t)
                        story.append(Spacer(1, 0.15*inch))
                    
                    elif img_result.get('status') == 'error':
                        error_para = Paragraph(
                            f"<b>Archivo:</b> {img_result.get('file', 'N/A')}<br/><i>Error: {img_result.get('error', 'Unknown')}</i>",
                            ParagraphStyle('error', parent=normal_style, textColor=colors.HexColor('#cc0000'))
                        )
                        story.append(error_para)
            
            story.append(Spacer(1, 0.2*inch))
    
    # Footer
    story.append(Spacer(1, 0.3*inch))
    footer_style = ParagraphStyle('footer', parent=normal_style, fontSize=8, textColor=colors.grey)
    footer = f"Generado: {data.get('started', datetime.now().isoformat())} | Orquestador OSINT v1.0"
    story.append(Paragraph(footer, footer_style))
    
    doc.build(story)
    return output_path
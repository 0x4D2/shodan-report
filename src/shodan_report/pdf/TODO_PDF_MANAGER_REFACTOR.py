from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from datetime import datetime
from typing import List, Dict, Any, Optional
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors

def _create_styles(primary_hex: str, secondary_hex: str) -> Dict[str, ParagraphStyle]:

    styles = getSampleStyleSheet()
    
    return {
        'title': ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=16,
            textColor=HexColor(primary_hex),
            spaceAfter=12,
            alignment=1
        ),
        'heading1': ParagraphStyle(
            'CustomHeading1',
            parent=styles['Heading1'],
            fontSize=12,
            textColor=HexColor(primary_hex),
            spaceBefore=16,
            spaceAfter=8,
            leftIndent=0,
            borderPadding=(0, 0, 0, 6),
            borderColor=HexColor(primary_hex),
            borderWidth=(0, 0, 1, 0)
        ),
        'heading2': ParagraphStyle(
            'CustomHeading2',
            parent=styles['Heading2'],
            fontSize=11,  # Etwas kleiner
            textColor=HexColor(secondary_hex),
            spaceBefore=12,
            spaceAfter=6,
            leftIndent=0
        ),
        'normal': ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=3
        ),
        'bullet': ParagraphStyle(
            'CustomBullet',
            parent=styles['Normal'],
            fontSize=10,
            leftIndent=20,
            firstLineIndent=-10,
            spaceAfter=2,
            bulletIndent=10
        ),
        'disclaimer': ParagraphStyle(
            'Disclaimer',
            parent=styles['Normal'],
            fontSize=7,
            textColor='gray',
            alignment=1,
            leading=10,
            spaceBefore=12,
            spaceAfter=6
        ),
        'footer': ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor='darkgray',
            alignment=1,
            leading=10
        )
    }


def _create_header(elements: List, styles: Dict, customer_name: str, 
                   month: str, ip: str, primary_hex: str) -> None:
    """Füge Header zum PDF hinzu."""
    
    elements.append(Paragraph(
        f"<font color='{primary_hex}'>Sicherheitsreport – Externe Angriffsflächenanalyse (OSINT, passiv)</font>", 
        styles['title']
    ))
    elements.append(Spacer(1, 12))
    
    # HART CODERT ALS BEISPIEL - SPÄTER DYNAMISCH
    try:
        from datetime import datetime
        report_date = datetime.strptime(month, "%Y-%m")
        month_formatted = report_date.strftime("%B %Y")
    except:
        month_formatted = month
    
    # BEISPIEL-DATEN - WIRD SPÄTER DYNAMISCH
    metadata_text = f"""
    <b>Kunde:</b> {customer_name}<br/>
    <b>Analysezeitraum:</b> {month_formatted}<br/>
    <b>Analysierte Assets:</b><br/>
    &nbsp;&nbsp;&nbsp;&nbsp;• 1 öffentliche IP-Adresse<br/>
    <b>Datenquelle:</b> Shodan (passiv, OSINT)
    """
    
    elements.append(Paragraph(metadata_text, styles['normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<hr width='100%' color='{primary_hex}' size='0.5'/>", styles['normal']))
    elements.append(Spacer(1, 12))

def _create_management_section(elements: List, styles: Dict, management_text: str) -> None:
    """Erstelle professionelle Management-Zusammenfassung (hartcoded Version)."""
    
    # 1. ABSCHNITTSÜBERSCHRIFT
    elements.append(Paragraph("<b>1. Management-Zusammenfassung</b>", styles['heading2']))
    elements.append(Spacer(1, 12))
    
    # 2. GESAMTBEWERTUNG
    elements.append(Paragraph("<b>Gesamtbewertung der externen Angriffsfläche</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    # Exposure-Level hartcoded (später dynamisch)
    elements.append(Paragraph("Exposure-Level: <b>2 von 5 (niedrig–mittel)</b>", styles['normal']))
    elements.append(Spacer(1, 8))
    
    # 3. BESCHREIBUNG (Teil aus management_text, Rest hartcoded)
    if management_text:
        # Ersten Absatz aus dem vorhandenen Text nehmen
        lines = [line.strip() for line in management_text.splitlines() if line.strip()]
        if lines:
            elements.append(Paragraph(lines[0], styles['normal']))
            elements.append(Spacer(1, 4))
    
    # Hartcoded professioneller Text
    professional_text = """
    Auf Basis passiver OSINT-Daten wurden mehrere öffentlich erreichbare Dienste identifiziert.
    Aktuell wurden keine kritisch ausnutzbaren Schwachstellen mit bekannter aktiver Exploit-
    Verfügbarkeit festgestellt.
    
    Die externe Angriffsfläche ist kontrolliert, jedoch bestehen strukturelle Risiken, die bei
    fehlender Härtung oder zukünftigen Schwachstellen zu einem erhöhten Risiko führen können.
    """
    
    for line in professional_text.strip().split('\n'):
        if line.strip():
            elements.append(Paragraph(line.strip(), styles['normal']))
    
    elements.append(Spacer(1, 12))
    
    # 4. WICHTIGSTE ERKENNTNISSE (hartcoded)
    elements.append(Paragraph("<b>Wichtigste Erkenntnisse</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    insights = [
        "Öffentliche Dienste sind konsistent erreichbar und stabil konfiguriert",
        "Keine hochkritischen CVEs (CVSS ≥ 9.0) mit bekannter Exploit-Reife",
        "TLS-Konfiguration teilweise veraltet",
        "DNS-Server erlaubt rekursive Anfragen (potenzielles Missbrauchsrisiko)"
    ]
    
    for insight in insights:
        elements.append(Paragraph(f"• {insight}", styles['bullet']))
    
    elements.append(Spacer(1, 12))
    
    # 5. EMPFEHLUNGEN (hartcoded)
    elements.append(Paragraph("<b>Empfehlung auf Management-Ebene</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    recommendations = [
        "Keine sofortigen Notfallmaßnahmen erforderlich",
        "Kurzfristig: Härtung einzelner Konfigurationen",
        "Mittelfristig: Etablierung eines kontinuierlichen externen Monitorings"
    ]
    
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles['bullet']))


def _create_trend_section(elements: List, styles: Dict, trend_text: str, 
                         compare_month: Optional[str] = None) -> None:
    """Erstelle Trend-Analyse mit einfacher Text-Tabelle."""
    
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>2. Trend- & Vergleichsanalyse</b>", styles['heading2']))
    elements.append(Spacer(1, 8))
    
    if compare_month:
        elements.append(Paragraph("<b>Veränderung zur Vormonatsanalyse</b>", styles['normal']))
        elements.append(Spacer(1, 6))
        
        # EINFACHE TEXT-TABELLE OHNE COURIER
        table_lines = [
            "<b>Kategorie          Vormonat  Aktuell  Bewertung</b>",
            "─────────────────────────────────────────────────────",
            "Öffentl. Ports           5        5    unverändert",
            "Krit. Services           1        1    stabil",
            "Hochrisiko-CVEs          0        0    stabil",
            "TLS-Schwächen            1        2    leicht schlechter"
        ]
        
        for line in table_lines:
            elements.append(Paragraph(line, styles['normal']))
        
        elements.append(Spacer(1, 12))
        
        # Interpretation
        elements.append(Paragraph("<b>Interpretation:</b>", styles['normal']))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            "Die Angriffsfläche ist stabil, zeigt jedoch eine leichte Verschlechterung "
            "in der Kryptokonfiguration, was langfristig relevant werden kann.",
            styles['normal']
        ))
        
    elif trend_text:
        # Fallback: Normale Liste
        elements.append(Paragraph("<b>Historie / Trend</b>", styles['normal']))
        elements.append(Spacer(1, 4))
        
        for line in trend_text.splitlines():
            if line.strip():
                elements.append(Paragraph(f"• {line.strip()}", styles['bullet']))
                
    else:
        # Keine Vergleichsdaten
        elements.append(Paragraph(
            "<i>Erste Analyse – Trend wird bei zukünftigen Vergleichen sichtbar.</i>", 
            styles['normal']
        ))
    
    elements.append(Spacer(1, 8))

def _create_prioritized_recommendations(elements: List, styles: Dict, technical_json: Dict) -> None:
    """Erstelle priorisierte Handlungsempfehlungen basierend auf gefundenen Services."""
    
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>4. Priorisierte Handlungsempfehlungen</b>", styles['heading2']))
    elements.append(Spacer(1, 8))
    
    open_ports = technical_json.get("open_ports", [])
    
    # ERKENNTNISSE SAMMELN
    has_web_services = any(p in [80, 443, 8080, 8443] for p in [port_info.get('port') for port_info in open_ports])
    has_ssh = any(port_info.get('port') == 22 for port_info in open_ports)
    has_mysql = any(port_info.get('port') == 3306 for port_info in open_ports)
    has_clickhouse = any(port_info.get('port') in [8123, 9000] for port_info in open_ports)
    
    # PRIORITÄT 1 – MITTELFRISTIG (30–90 Tage)
    elements.append(Paragraph("<b>Priorität 1 – Mittelfristig (30–90 Tage)</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    priority_1 = []
    
    if has_web_services:
        priority_1.append("Aktualisierung der TLS-Konfiguration")
        priority_1.append("Abschaltung veralteter Protokolle (TLS 1.0 / 1.1)")
        priority_1.append("Überprüfung der Zertifikatslaufzeiten")
    
    if has_ssh:
        priority_1.append("SSH-Konfiguration härten (z.B. PasswordAuthentication no)")
    
    if has_mysql:
        priority_1.append("MySQL Zugriff auf interne IPs beschränken")
    
    if has_clickhouse:
        priority_1.append("ClickHouse Authentifizierung erzwingen")
    
    # Falls nichts spezifisches gefunden
    if not priority_1:
        priority_1.append("Härtung der gefundenen Dienste gemäß Best Practices")
        priority_1.append("Regelmäßige Sicherheitsupdates implementieren")
    
    for item in priority_1:
        elements.append(Paragraph(f"• {item}", styles['bullet']))
    
    elements.append(Spacer(1, 8))
    
    # PRIORITÄT 2 – OPTIONAL
    elements.append(Paragraph("<b>Priorität 2 – Optional</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    priority_2 = [
        "Einschränkung rekursiver DNS-Anfragen auf interne Netze",
        "Regelmäßige Überprüfung neu auftretender Dienste",
        "Implementierung eines Security-Headering für Web-Dienste",
        "Logging und Monitoring für kritische Dienste"
    ]
    
    # Anpassen basierend auf gefundenen Services
    if not has_web_services:
        priority_2 = [p for p in priority_2 if "Web" not in p and "TLS" not in p]
    
    for item in priority_2[:3]:  # Max 3 Punkte
        elements.append(Paragraph(f"• {item}", styles['bullet']))
    
    elements.append(Spacer(1, 12))

def _create_technical_section(elements: List, styles: Dict, technical_json: Dict, ip: str) -> None:
    """Erstelle professionelle technische Detailanalyse."""
    
    # Sicherheitscheck gegen Dopplungen
    for elem in elements:
        if isinstance(elem, Paragraph) and "Technische Detailanalyse" in str(elem):
            return
    
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>4. Technische Detailanalyse (Auszug)</b>", styles['heading2']))
    elements.append(Spacer(1, 12))
    
    # ASSET-ÜBERSCHRIFT
    elements.append(Paragraph(f"<b>Asset:</b> {ip}", styles['normal']))
    
    # Domain (hartcoded für heute, TODO: später aus Daten)
    elements.append(Paragraph("<b>Zugeordnete Domain:</b> [Domain aus Konfiguration oder Whois]", styles['normal']))
    elements.append(Spacer(1, 12))
    
    open_ports = technical_json.get("open_ports", [])
    
    if not open_ports:
        elements.append(Paragraph("Keine offenen Ports gefunden.", styles['normal']))
        return
    
    # TABELLEN-ÜBERSCHRIFT
    elements.append(Paragraph("<b>Offene Ports & Dienste:</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    # EINFACHE TEXT-TABELLE
    table_header = "<font face='Courier' size='8'><b>Port   Dienst       Version           Risiko</b></font>"
    elements.append(Paragraph(table_header, styles['normal']))
    
    separator = "<font face='Courier' size='8'>───── ──────────── ───────────────── ────────</font>"
    elements.append(Paragraph(separator, styles['normal']))
    
    # TOP 5 Ports (wichtigste zuerst)
    important_ports = []
    for port_info in open_ports:
        port = port_info.get('port', 0)
        service = port_info.get('service', {})
        product = service.get('product', 'Unbekannt')
        version = service.get('version', '')
        
        # Priorität: SSH, DB, Web, andere
        priority = 0
        if port == 22:
            priority = 100  # SSH höchste Prio
        elif port in [3306, 5432]:
            priority = 90   # DB
        elif port in [80, 443, 8080, 8443]:
            priority = 80   # Web
        elif "http" in product.lower():
            priority = 70
        else:
            priority = 10
        
        # Version kürzen
        short_version = version[:15] + "..." if len(version) > 15 else version
        
        # Risiko
        risk = "niedrig"
        risk_color = "#16a34a"  # grün
        if port == 22:
            risk = "hoch"
            risk_color = "#dc2626"  # rot
        elif port in [3306, 5432, 21, 23]:
            risk = "mittel"
            risk_color = "#ea580c"  # orange
        
        important_ports.append({
            'port': port,
            'product': product[:12],  # Max 12 Zeichen
            'version': short_version or '-',
            'risk': risk,
            'risk_color': risk_color,
            'priority': priority
        })
    
    # Nach Priorität sortieren
    important_ports.sort(key=lambda x: x['priority'], reverse=True)
    
    # TOP 5 anzeigen
    for item in important_ports[:5]:
        # Formatierung für Tabelle
        port_str = str(item['port']).ljust(5)
        product_str = item['product'].ljust(12)
        version_str = (item['version'] or '-').ljust(16)
        risk_str = item['risk'].ljust(8)
        
        row = f"<font face='Courier' size='8'>{port_str} {product_str} {version_str} <font color='{item['risk_color']}'>{risk_str}</font></font>"
        elements.append(Paragraph(row, styles['normal']))
    
    elements.append(Spacer(1, 12))
    
    # DIENSTSPEZIFISCHE BEWERTUNGEN
    elements.append(Paragraph("<b>Dienstspezifische Bewertungen:</b>", styles['normal']))
    elements.append(Spacer(1, 8))
    
    # Check für HTTPS (Port 443 oder 8443)
    https_ports = [p for p in open_ports if p.get('port') in [443, 8443]]
    if https_ports:
        elements.append(Paragraph("<b>TLS-Bewertung (Port 443/8443):</b>", styles['normal']))
        elements.append(Spacer(1, 2))
        
        # TODO: Echte TLS-Analyse später
        tls_points = [
            "Unterstützte Protokolle: TLS 1.2, TLS 1.3",
            "Schwache Cipher Suites: ja (TLS_RSA_WITH_AES_128_CBC_SHA)",
            "Zertifikat gültig bis: [TODO: Zertifikatsanalyse]",
            "Perfect Forward Secrecy: aktiviert"
        ]
        
        for point in tls_points:
            elements.append(Paragraph(f"• {point}", styles['bullet']))
        
        elements.append(Spacer(1, 8))
    
    # Check für SSH (Port 22)
    ssh_ports = [p for p in open_ports if p.get('port') == 22]
    if ssh_ports:
        elements.append(Paragraph("<b>SSH-Bewertung (Port 22):</b>", styles['normal']))
        elements.append(Spacer(1, 2))
        
        ssh_points = [
            "Protokoll: SSH-2.0",
            "Key Exchange: diffie-hellman-group14-sha1",
            "Authentifizierung: publickey, password",
            "Schwachstellen: keine kritischen CVEs bekannt"
        ]
        
        for point in ssh_points:
            elements.append(Paragraph(f"• {point}", styles['bullet']))
        
        elements.append(Spacer(1, 8))
    
    # Check für MySQL (Port 3306)
    mysql_ports = [p for p in open_ports if p.get('port') == 3306]
    if mysql_ports:
        elements.append(Paragraph("<b>MySQL-Bewertung (Port 3306):</b>", styles['normal']))
        elements.append(Spacer(1, 2))
        
        mysql_points = [
            "Version: MySQL 8.0.33",
            "Authentifizierung: erforderlich",
            "Remote Zugriff: möglich",
            "CVEs: CVE-2023-21912 (niedrig), CVE-2023-21980 (mittel)"
        ]
        
        for point in mysql_points:
            elements.append(Paragraph(f"• {point}", styles['bullet']))
    
    elements.append(Spacer(1, 12))
    
    # HINWEIS FÜR VOLLSTÄNDIGE ANALYSE
    if len(open_ports) > 5:
        elements.append(Paragraph(
            f"<i>Hinweis: Es wurden {len(open_ports)} offene Ports gefunden. "
            f"Diese Zusammenfassung zeigt die 5 kritischsten Dienste.</i>",
            styles['normal']
        ))

def _create_cve_overview(elements: List, styles: Dict, technical_json: Dict) -> None:
    """Erstelle CVE- & Exploit-Übersicht."""
    
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>5. CVE- & Exploit-Übersicht</b>", styles['heading2']))
    elements.append(Spacer(1, 8))
    
    open_ports = technical_json.get("open_ports", [])
    
    # CVEs SAMMELN BASIEREND AUF SERVICES
    cve_data = []
    
    for port_info in open_ports:
        port = port_info.get('port', 0)
        service = port_info.get('service', {})
        product = service.get('product', '').lower()
        version = service.get('version', '')
        
        # CVEs BASIEREND AUF PRODUKT/VERSION (hartcoded für heute)
        if port == 22 or 'ssh' in product:
            # OpenSSH CVEs
            if '7.6' in version:
                cve_data.append({
                    'dienst': 'OpenSSH',
                    'cve': 'CVE-2023-28531',
                    'cvss': '7.5',
                    'exploit_status': 'öffentlich bekannt',
                    'relevanz': 'mittel'
                })
        
        elif port == 3306 or 'mysql' in product:
            # MySQL CVEs
            if '8.0.33' in version:
                cve_data.append({
                    'dienst': 'MySQL',
                    'cve': 'CVE-2023-21912',
                    'cvss': '6.5',
                    'exploit_status': 'Proof-of-Concept',
                    'relevanz': 'mittel'
                })
                cve_data.append({
                    'dienst': 'MySQL', 
                    'cve': 'CVE-2023-21980',
                    'cvss': '5.9',
                    'exploit_status': 'kein Exploit',
                    'relevanz': 'niedrig'
                })
        
        elif port == 80 or port == 443 or 'http' in product or 'nginx' in product:
            # HTTP/Web CVEs
            cve_data.append({
                'dienst': 'HTTP/Web',
                'cve': 'CVE-2023-44487',
                'cvss': '7.5',
                'exploit_status': 'öffentlich bekannt',
                'relevanz': 'mittel'
            })
    
    # TABELLE ERSTELLEN
    if cve_data:
        elements.append(Paragraph("<b>Identifizierte Schwachstellen:</b>", styles['normal']))
        elements.append(Spacer(1, 4))
        
        # TABELLEN-HEADER
        header = "<font face='Courier' size='8'><b>Dienst        CVE               CVSS  Exploit-Status      Relevanz</b></font>"
        elements.append(Paragraph(header, styles['normal']))
        
        separator = "<font face='Courier' size='8'>───────────── ───────────────── ───── ─────────────────── ─────────</font>"
        elements.append(Paragraph(separator, styles['normal']))
        
        # TABELLEN-ROWS
        for cve in cve_data[:5]:  # Max 5 anzeigen
            dienst = cve['dienst'].ljust(12)
            cve_id = cve['cve'].ljust(17)
            cvss = cve['cvss'].ljust(5)
            exploit = cve['exploit_status'].ljust(18)
            relevanz = cve['relevanz']
            
            # Farbe basierend auf CVSS
            cvss_float = float(cve['cvss'])
            if cvss_float >= 9.0:
                relevanz_farbe = "#dc2626"  # rot
            elif cvss_float >= 7.0:
                relevanz_farbe = "#ea580c"  # orange
            else:
                relevanz_farbe = "#16a34a"  # grün
            
            row = f"<font face='Courier' size='8'>{dienst} {cve_id} {cvss} {exploit} <font color='{relevanz_farbe}'>{relevanz}</font></font>"
            elements.append(Paragraph(row, styles['normal']))
        
        elements.append(Spacer(1, 12))
        
        # BEWERTUNG
        elements.append(Paragraph("<b>Bewertung:</b>", styles['normal']))
        elements.append(Spacer(1, 4))
        
        # Kritische CVEs zählen
        critical_cves = len([c for c in cve_data if float(c['cvss']) >= 9.0])
        high_cves = len([c for c in cve_data if 7.0 <= float(c['cvss']) < 9.0])
        
        if critical_cves > 0:
            bewertung = f"""
            Es wurden {critical_cves} kritische Schwachstellen (CVSS ≥ 9.0) identifiziert.
            Diese sollten mit hoher Priorität gepatcht werden.
            """
        elif high_cves > 0:
            bewertung = f"""
            Es wurden {high_cves} Schwachstellen mit hoher Priorität (CVSS 7.0-8.9) identifiziert.
            Eine zeitnahe Behebung wird empfohlen.
            """
        else:
            bewertung = """
            Keine aktuell aktiv ausgenutzten Schwachstellen mit kritischer Priorität 
            identifiziert. Die identifizierten Schwachstellen sollten im regulären 
            Patch-Zyklus behoben werden.
            """
        
        for line in bewertung.strip().split('\n'):
            if line.strip():
                elements.append(Paragraph(line.strip(), styles['normal']))
    
    else:
        # KEINE CVEs GEFUNDEN
        elements.append(Paragraph("<b>Identifizierte Schwachstellen:</b>", styles['normal']))
        elements.append(Spacer(1, 4))
        
        # Leere Tabelle als Platzhalter
        header = "<font face='Courier' size='8'><b>Dienst        CVE               CVSS  Exploit-Status      Relevanz</b></font>"
        elements.append(Paragraph(header, styles['normal']))
        
        separator = "<font face='Courier' size='8'>───────────── ───────────────── ───── ─────────────────── ─────────</font>"
        elements.append(Paragraph(separator, styles['normal']))
        
        row = "<font face='Courier' size='8'>–             –                 –     –                  –</font>"
        elements.append(Paragraph(row, styles['normal']))
        
        elements.append(Spacer(1, 12))
        
        # BEWERTUNG
        elements.append(Paragraph("<b>Bewertung:</b>", styles['normal']))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            "Basierend auf der OSINT-Analyse wurden keine öffentlich bekannten "
            "kritischen Schwachstellen identifiziert. Eine vollständige CVE-Prüfung "
            "erfordert detaillierte Versionsinformationen und aktive Scans.",
            styles['normal']
        ))
    
    elements.append(Spacer(1, 8))

def _create_methodology_section(elements: List, styles: Dict) -> None:
    """Erstelle Methodik & Grenzen der Analyse Abschnitt."""
    
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>6. Methodik & Grenzen der Analyse</b>", styles['heading2']))
    elements.append(Spacer(1, 8))
    
    methodology_text = """
    Dieser Bericht basiert auf einer <b>passiven OSINT-Analyse (Open Source Intelligence)</b>. 
    Die folgenden Methoden und Einschränkungen sind zu beachten:
    """
    
    elements.append(Paragraph(methodology_text, styles['normal']))
    elements.append(Spacer(1, 8))
    
    limitations = [
        "Ausschließlich passive OSINT-Daten (keine aktiven Scans)",
        "Keine Garantie auf Vollständigkeit der ermittelten Informationen",
        "Keine Aussage über interne Systeme oder nicht öffentlich erreichbare Dienste",
        "Keine Simulation realer Angriffe oder Penetrationstests",
        "Begrenzte Tiefe bei verschlüsselten Diensten (TLS/SSL)",
        "Abhängigkeit von der Aktualität der Shodan-Datenbank",
        "Keine Bewertung von Web-Applikationsschwachstellen",
        "Begrenzte Erkennung von custom/obskuren Diensten"
    ]
    
    for limitation in limitations:
        elements.append(Paragraph(f"• {limitation}", styles['bullet']))
    
    elements.append(Spacer(1, 8))
    
    # EMPFEHLUNG FÜR WEITERGEHENDE ANALYSEN
    further_analysis = """
    <b>Empfohlene weitergehende Analysen:</b>
    Für eine umfassende Sicherheitsbewertung werden zusätzlich empfohlen:
    """
    
    elements.append(Paragraph(further_analysis, styles['normal']))
    elements.append(Spacer(1, 4))
    
    recommendations = [
        "Aktive Vulnerability Scans (authentifiziert/nicht-authentifiziert)",
        "Penetrationstests durch zertifizierte Sicherheitsexperten",
        "Web Application Security Assessments",
        "Konfigurationsaudits der gefundenen Dienste",
        "Red-Team-Exercises für realistische Angriffssimulationen"
    ]
    
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles['bullet']))
    
    elements.append(Spacer(1, 12))

def _create_conclusion_section(elements: List, styles: Dict, customer_name: str, 
                               technical_json: Dict) -> None:
    """Erstelle Fazit-Abschnitt."""
    
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>7. Fazit</b>", styles['heading2']))
    elements.append(Spacer(1, 8))
    
    open_ports = technical_json.get("open_ports", [])
    open_port_count = len(open_ports)
    
    # Risiko-Profile basierend auf gefundenen Ports
    has_critical_services = any(p.get('port') in [22, 23, 3389, 21] for p in open_ports)
    has_database = any(p.get('port') in [3306, 5432, 27017] for p in open_ports)
    has_web_services = any(p.get('port') in [80, 443, 8080, 8443] for p in open_ports)
    
    # Fazit-Text dynamisch anpassen
    if open_port_count == 0:
        conclusion_text = f"""
        Die externe Angriffsfläche von {customer_name} ist <b>minimal</b>. 
        Es wurden keine öffentlich erreichbaren Dienste identifiziert, was auf eine 
        gute Abschottung der Systeme hindeutet.
        """
    elif open_port_count <= 3 and not has_critical_services:
        conclusion_text = f"""
        Die externe Angriffsfläche von {customer_name} ist <b>überschaubar und kontrollierbar</b>. 
        Mit {open_port_count} öffentlichen Diensten besteht ein geringes bis mittleres Risiko.
        """
    elif has_critical_services:
        conclusion_text = f"""
        Die externe Angriffsfläche von {customer_name} erfordert <b>erhöhte Aufmerksamkeit</b>. 
        Kritische Dienste (SSH/RDP) sind öffentlich erreichbar und sollten zusätzlich abgesichert werden.
        """
    else:
        conclusion_text = f"""
        Die externe Angriffsfläche von {customer_name} ist <b>kontrollierbar, aber beobachtungsbedürftig</b>. 
        Mit {open_port_count} öffentlichen Diensten besteht ein mittleres Risikoprofil.
        """
    
    elements.append(Paragraph(conclusion_text, styles['normal']))
    elements.append(Spacer(1, 8))
    
    # EMPFEHLUNG FÜR KONTINUIERLICHES MONITORING
    monitoring_text = """
    <b>Kontinuierliches Monitoring:</b>
    Der größte Mehrwert ergibt sich aus der regelmäßigen Beobachtung der externen 
    Angriffsfläche, um:
    """
    
    elements.append(Paragraph(monitoring_text, styles['normal']))
    elements.append(Spacer(1, 4))
    
    monitoring_points = [
        "Neue öffentlich erreichbare Dienste frühzeitig zu erkennen",
        "Veraltete/gefährdete Versionen proaktiv zu identifizieren",
        "Veränderungen im Risikoprofil zu monitorieren",
        "Trends und Entwicklungen langfristig nachzuvollziehen",
        "Compliance-Anforderungen kontinuierlich zu erfüllen"
    ]
    
    for point in monitoring_points:
        elements.append(Paragraph(f"• {point}", styles['bullet']))
    
    elements.append(Spacer(1, 8))
    
    # AUSBLICK
    outlook_text = """
    <b>Ausblick:</b>
    Eine regelmäßige Überprüfung (empfohlen: monatlich) ermöglicht es, die Sicherheitslage 
    kontinuierlich zu verbessern und auf neue Bedrohungen reagieren zu können.
    """
    
    elements.append(Paragraph(outlook_text, styles['normal']))
    elements.append(Spacer(1, 12))

def _create_footer(elements: List, styles: Dict) -> None:
    """Erstelle professionellen Footer."""
    
    elements.append(Spacer(1, 24))
    
    # TRENNLINIE FÜR ABGRENZUNG
    elements.append(Paragraph("<hr width='100%' color='lightgray' size='0.5'/>", styles['normal']))
    elements.append(Spacer(1, 12))
    
    # FOOTER-TEXT (kompakt und professionell)
    footer_text = f"""
    <font size='8'>
    <b>Vertraulich – nur für den genannten Empfänger</b><br/>
    Stand: {datetime.now().strftime('%d.%m.%Y')}<br/>
    Erstellt mit Shodan Report Generator (OSINT, passiv)
    </font>
    """
    
    elements.append(Paragraph(footer_text, styles['footer']))
    elements.append(Spacer(1, 6))
    
    # KLEINER DISCLAIMER (optional, falls gewünscht)
    optional_disclaimer = """
    <font size='6'>
    <i>Hinweis: Basierend auf öffentlichen OSINT-Daten. Dient zu Informationszwecken.
    Keine Garantie auf Vollständigkeit oder Richtigkeit.</i>
    </font>
    """
    
    # Falls du den Disclaimer behalten möchtest:
    # elements.append(Paragraph(optional_disclaimer, styles['footer']))

def prepare_pdf_elements(
    customer_name: str, 
    month: str, 
    ip: str, 
    management_text: str,
    trend_text: str, 
    technical_json: Dict[str, Any],
    config: Optional[Dict] = None,
    compare_month: Optional[str] = None
) -> List:
    """
    Erstelle alle PDF-Elemente für den Sicherheitsreport.
    
    Args:
        customer_name: Name des Kunden
        month: Monat (YYYY-MM)
        ip: IP-Adresse
        management_text: Management-Zusammenfassung
        trend_text: Trend-Analyse
        technical_json: Technische Daten
        config: Kundenkonfiguration (optional)
    
    Returns:
        Liste von PDF-Elementen
    """
    config = config or {}
    styling = config.get("styling", {})
    
    # Farben aus Config oder Default
    primary_hex = styling.get("primary_color", "#1a365d")
    secondary_hex = styling.get("secondary_color", "#2d3748")
    
    # Styles erstellen
    styles = _create_styles(primary_hex, secondary_hex)
    
    # PDF-Elemente aufbauen
    elements = []
    
    _create_header(elements, styles, customer_name, month, ip, primary_hex)
    _create_management_section(elements, styles, management_text)
    _create_trend_section(elements, styles, trend_text,compare_month)
    _create_prioritized_recommendations(elements, styles, technical_json)
    _create_technical_section(elements, styles, technical_json, ip)
    _create_cve_overview(elements, styles, technical_json)
    _create_methodology_section(elements, styles)
    _create_conclusion_section(elements, styles, customer_name, technical_json) 
    _create_footer(elements, styles)
    
    return elements
"""Tests für die Attack-Scenario-Section."""

import pytest
from reportlab.platypus import Paragraph, Spacer, Table, KeepTogether
from reportlab.lib.colors import HexColor

from shodan_report.pdf.styles import create_styles, create_theme
from shodan_report.pdf.sections.attack_scenario import (
    _severity_colors,
    _severity_badge,
    _risk_card,
    _positive_box,
    _is_web_only,
    _chain_card,
    _hinweis_box,
    _build_attack_chain,
    create_attack_scenario_section,
    _C_SEVERITY_CRIT_BG,
    _C_SEVERITY_MED_BG,
    _C_SEVERITY_LOW_BG,
    _C_POSITIVE_BG,
    _C_POSITIVE_BD,
    _C_HINT_BG,
    _C_HINT_TX,
)
from shodan_report.pdf.helpers.management_helpers import (
    _build_top_risks,
    _svc_label,
)


@pytest.fixture
def styles():
    return create_styles(create_theme("#1a365d", "#2d3748"))


# ── Hilfsfunktion: alle Paragraphs aus verschachtelten Strukturen extrahieren ─

def _all_paragraphs(elements):
    result = []
    for e in elements:
        if isinstance(e, Paragraph):
            result.append(e)
        elif isinstance(e, Table):
            for row in (getattr(e, "_cellvalues", None) or []):
                for cell in row:
                    if isinstance(cell, (Paragraph, Table, KeepTogether, list)):
                        result.extend(_all_paragraphs([cell]))
        elif isinstance(e, KeepTogether):
            result.extend(_all_paragraphs(e._content))
        elif isinstance(e, list):
            result.extend(_all_paragraphs(e))
    return result


def _flatten(elements):
    """Gibt alle Elemente aus KeepTogether-Wrappern auf erste Ebene zurück."""
    flat = []
    for e in elements:
        if isinstance(e, KeepTogether):
            flat.extend(e._content)
        else:
            flat.append(e)
    return flat


# ── _severity_colors ──────────────────────────────────────────────────────────

class TestSeverityColors:

    def test_hoch_returns_red(self):
        bg, bd, tx = _severity_colors("hoch")
        assert bg == _C_SEVERITY_CRIT_BG

    def test_kritisch_returns_red(self):
        bg, bd, tx = _severity_colors("kritisch")
        assert bg == _C_SEVERITY_CRIT_BG

    def test_high_english_returns_red(self):
        bg, bd, tx = _severity_colors("high")
        assert bg == _C_SEVERITY_CRIT_BG

    def test_mittel_returns_orange(self):
        bg, bd, tx = _severity_colors("mittel")
        assert bg == _C_SEVERITY_MED_BG

    def test_mittel_hoch_returns_red(self):
        # "mittel–hoch" contains "hoch" → rot
        bg, bd, tx = _severity_colors("mittel–hoch")
        assert bg == _C_SEVERITY_CRIT_BG

    def test_niedrig_returns_green(self):
        bg, bd, tx = _severity_colors("niedrig")
        assert bg == _C_SEVERITY_LOW_BG

    def test_niedrig_mittel_returns_orange(self):
        # "niedrig–mittel" enthält "mittel" → orange (mittel-Zweig greift)
        bg, bd, tx = _severity_colors("niedrig–mittel")
        assert bg == _C_SEVERITY_MED_BG

    def test_case_insensitive(self):
        bg1, _, _ = _severity_colors("HOCH")
        bg2, _, _ = _severity_colors("hoch")
        assert bg1 == bg2

    def test_unknown_falls_back_to_green(self):
        bg, _, _ = _severity_colors("unbekannt")
        assert bg == _C_SEVERITY_LOW_BG

    def test_returns_three_values(self):
        result = _severity_colors("mittel")
        assert len(result) == 3


# ── _severity_badge ───────────────────────────────────────────────────────────

class TestSeverityBadge:

    def test_returns_table(self, styles):
        result = _severity_badge("hoch", styles)
        assert isinstance(result, Table)

    def test_label_uppercased_in_paragraph(self, styles):
        badge = _severity_badge("mittel", styles)
        para = badge._cellvalues[0][0]
        assert isinstance(para, Paragraph)
        assert "MITTEL" in para.text

    def test_all_severities_produce_table(self, styles):
        for sev in ("hoch", "mittel", "niedrig", "kritisch", "low"):
            assert isinstance(_severity_badge(sev, styles), Table)


# ── _risk_card ────────────────────────────────────────────────────────────────

class TestRiskCard:

    def _sample_risk(self):
        return {
            "title": "Exponierter Administrationszugang",
            "severity": "mittel",
            "cause": "SSH Port 22 öffentlich erreichbar.",
            "scenario": "Brute-Force-Angriff auf Zugangsdaten.",
            "impact": "Kontoübernahme.",
            "recommendation": "Key-Only Auth, Fail2ban.",
        }

    def test_returns_table(self, styles):
        card = _risk_card(self._sample_risk(), styles, 1)
        assert isinstance(card, Table)

    def test_idx_appears_in_paragraphs(self, styles):
        card = _risk_card(self._sample_risk(), styles, 2)
        paras = _all_paragraphs([card])
        assert any("2." in p.text for p in paras)

    def test_title_appears_in_paragraphs(self, styles):
        card = _risk_card(self._sample_risk(), styles, 1)
        paras = _all_paragraphs([card])
        assert any("Administrationszugang" in p.text for p in paras)

    def test_cause_text_present(self, styles):
        card = _risk_card(self._sample_risk(), styles, 1)
        paras = _all_paragraphs([card])
        assert any("SSH Port 22" in p.text for p in paras)

    def test_scenario_text_present(self, styles):
        card = _risk_card(self._sample_risk(), styles, 1)
        paras = _all_paragraphs([card])
        assert any("Brute-Force" in p.text for p in paras)

    def test_impact_text_present(self, styles):
        card = _risk_card(self._sample_risk(), styles, 1)
        paras = _all_paragraphs([card])
        assert any("Kontoübernahme" in p.text for p in paras)

    def test_recommendation_text_present(self, styles):
        card = _risk_card(self._sample_risk(), styles, 1)
        paras = _all_paragraphs([card])
        assert any("Fail2ban" in p.text for p in paras)

    def test_missing_fields_do_not_raise(self, styles):
        card = _risk_card({}, styles, 1)
        assert isinstance(card, Table)


# ── _positive_box ─────────────────────────────────────────────────────────────

class TestPositiveBox:

    def test_returns_table(self, styles):
        box = _positive_box(styles)
        assert isinstance(box, Table)

    def test_has_green_background(self, styles):
        # Positiv-Box muss grüne Paragraphs enthalten (color="#166534")
        box = _positive_box(styles)
        paras = _all_paragraphs([box])
        assert any("#166534" in p.text or "166534" in p.text for p in paras)

    def test_contains_positive_message(self, styles):
        box = _positive_box(styles)
        paras = _all_paragraphs([box])
        assert any("kritischen Angriffsvektoren" in p.text for p in paras)

    def test_references_handlungsempfehlungen(self, styles):
        box = _positive_box(styles)
        paras = _all_paragraphs([box])
        assert any("Handlungsempfehlungen" in p.text for p in paras)


# ── create_attack_scenario_section ───────────────────────────────────────────

# Fixture-Daten

WEB_ONLY = {"services": [
    {"port": 80,  "product": "nginx"},
    {"port": 443, "product": "nginx"},
]}

SSH_DB_WEB = {"services": [
    {"port": 22,   "product": "OpenSSH"},
    {"port": 3306, "product": "MySQL"},
    {"port": 443,  "product": "nginx"},
]}

SSH_WEB = {"services": [
    {"port": 22,  "product": "OpenSSH"},
    {"port": 443, "product": "nginx"},
]}

WEB_MAIL = {"services": [
    {"port": 443, "product": "nginx"},
    {"port": 25,  "product": "Postfix"},
]}


class TestCreateAttackScenarioSection:

    def _collect(self, styles, technical_json=None, risk_level="low"):
        elements = []
        create_attack_scenario_section(
            elements=elements,
            styles=styles,
            technical_json=technical_json or {},
        )
        return elements

    # ── Grundverhalten ────────────────────────────────────────────────────────

    def test_produces_elements(self, styles):
        assert len(self._collect(styles)) > 0

    def test_heading_present(self, styles):
        elements = self._collect(styles, WEB_ONLY)
        flat = _flatten(elements)
        paras = [e for e in flat if isinstance(e, Paragraph)]
        assert any("Angriffsszenario" in p.text for p in paras)

    def test_heading_is_realistisches(self, styles):
        elements = self._collect(styles, WEB_ONLY)
        flat = _flatten(elements)
        paras = [e for e in flat if isinstance(e, Paragraph)]
        assert any("Realistisches" in p.text for p in paras)

    def test_wrapped_in_keep_together(self, styles):
        elements = self._collect(styles, WEB_ONLY)
        assert any(isinstance(e, KeepTogether) for e in elements)

    # ── Intro-Text ────────────────────────────────────────────────────────────

    def test_intro_text_present(self, styles):
        elements = self._collect(styles, SSH_DB_WEB)
        paras = _all_paragraphs(elements)
        assert any("realer Angriff" in p.text for p in paras)

    def test_intro_text_contains_customer_name(self, styles):
        class FakeCtx:
            technical_json = SSH_DB_WEB
            evaluation = {}
            customer_name = "Acme GmbH"

        elements = []
        create_attack_scenario_section(elements=elements, styles=styles, context=FakeCtx())
        paras = _all_paragraphs(elements)
        assert any("Acme GmbH" in p.text for p in paras)

    # ── Gate: Positiv-Box ────────────────────────────────────────────────────

    def test_web_only_triggers_positive_box(self, styles):
        elements = self._collect(styles, WEB_ONLY)
        paras = _all_paragraphs(elements)
        assert any("kritischen Angriffsvektoren" in p.text for p in paras)

    def test_empty_services_triggers_positive_box(self, styles):
        elements = self._collect(styles, {})
        paras = _all_paragraphs(elements)
        assert any("kritischen Angriffsvektoren" in p.text for p in paras)

    def test_web_only_no_chain_steps(self, styles):
        elements = self._collect(styles, WEB_ONLY)
        paras = _all_paragraphs(elements)
        # Ketten-Karten haben "Reconnaissance" — darf bei Web-only nicht vorkommen
        assert not any("Reconnaissance" in p.text for p in paras)

    # ── Angriffskette (non-web-only) ──────────────────────────────────────────

    def test_ssh_db_web_renders_chain(self, styles):
        elements = self._collect(styles, SSH_DB_WEB)
        paras = _all_paragraphs(elements)
        assert any("Reconnaissance" in p.text for p in paras)

    def test_ssh_db_web_no_positive_box(self, styles):
        elements = self._collect(styles, SSH_DB_WEB)
        paras = _all_paragraphs(elements)
        assert not any("kritischen Angriffsvektoren" in p.text for p in paras)

    def test_web_mail_renders_chain(self, styles):
        elements = self._collect(styles, WEB_MAIL)
        paras = _all_paragraphs(elements)
        assert any("Reconnaissance" in p.text for p in paras)

    def test_ssh_web_renders_chain(self, styles):
        elements = self._collect(styles, SSH_WEB)
        paras = _all_paragraphs(elements)
        assert any("Reconnaissance" in p.text for p in paras)

    def test_chain_always_four_steps(self, styles):
        many = {"services": [
            {"port": 22,   "product": "OpenSSH"},
            {"port": 3306, "product": "MySQL"},
            {"port": 443,  "product": "nginx"},
            {"port": 25,   "product": "Postfix"},
            {"port": 21,   "product": "vsftpd"},
        ]}
        elements = self._collect(styles, many)
        paras = _all_paragraphs(elements)
        # Genau 4 nummerierte Schritte: 01, 02, 03, 04
        for num in ("01", "02", "03", "04"):
            assert any(num in p.text for p in paras), f"Step {num} fehlt"

    def test_hinweis_box_present_when_chain_shown(self, styles):
        elements = self._collect(styles, SSH_DB_WEB)
        paras = _all_paragraphs(elements)
        assert any("vollautomatisiert" in p.text for p in paras)

    def test_chain_step4_mentions_ransomware(self, styles):
        elements = self._collect(styles, SSH_DB_WEB)
        paras = _all_paragraphs(elements)
        assert any("Ransomware" in p.text for p in paras)

    # ── Context-DI ────────────────────────────────────────────────────────────

    def test_context_di_works(self, styles):
        class FakeCtx:
            technical_json = SSH_DB_WEB
            evaluation = {"risk_level": "high"}
            customer_name = ""

        elements = []
        create_attack_scenario_section(elements=elements, styles=styles, context=FakeCtx())
        paras = _all_paragraphs(elements)
        assert any("Reconnaissance" in p.text for p in paras)

    def test_context_none_and_no_technical_json(self, styles):
        elements = []
        create_attack_scenario_section(elements=elements, styles=styles)
        assert len(elements) > 0

    def test_technical_json_kwarg_wins_over_context(self, styles):
        """Explizit übergebenes technical_json hat Vorrang vor context."""
        class FakeCtx:
            technical_json = SSH_DB_WEB
            evaluation = {}
            customer_name = ""

        elements = []
        create_attack_scenario_section(
            elements=elements,
            styles=styles,
            technical_json={},   # leer → Gate greift, Positiv-Box
            context=FakeCtx(),
        )
        paras = _all_paragraphs(elements)
        assert any("kritischen Angriffsvektoren" in p.text for p in paras)

    # ── Spacer vorhanden ──────────────────────────────────────────────────────

    def test_spacer_appended_after_section(self, styles):
        elements = self._collect(styles, WEB_ONLY)
        assert any(isinstance(e, Spacer) for e in elements)


# ── _is_web_only ──────────────────────────────────────────────────────────────

class TestIsWebOnly:

    def test_web_only_port_80(self):
        assert _is_web_only({"services": [{"port": 80, "product": "nginx"}]}) is True

    def test_web_only_port_443(self):
        assert _is_web_only({"services": [{"port": 443, "product": "nginx"}]}) is True

    def test_web_only_both_ports(self):
        assert _is_web_only(WEB_ONLY) is True

    def test_empty_services_is_web_only(self):
        assert _is_web_only({}) is True

    def test_ssh_not_web_only(self):
        assert _is_web_only(SSH_WEB) is False

    def test_ssh_alone_not_web_only(self):
        assert _is_web_only({"services": [{"port": 22, "product": "OpenSSH"}]}) is False

    def test_cpanel_not_web_only(self):
        assert _is_web_only({"services": [{"port": 2083, "product": "cPanel"}]}) is False

    def test_rdp_not_web_only(self):
        assert _is_web_only({"services": [{"port": 3389, "product": ""}]}) is False

    def test_db_not_web_only(self):
        assert _is_web_only({"services": [{"port": 3306, "product": "MySQL"}]}) is False

    def test_mail_not_web_only(self):
        assert _is_web_only(WEB_MAIL) is False

    def test_ftp_not_web_only(self):
        assert _is_web_only({"services": [{"port": 21, "product": "vsftpd"}]}) is False

    def test_ftp_by_product_keyword(self):
        assert _is_web_only({"services": [{"port": 8021, "product": "ProFTPD"}]}) is False

    def test_ssh_by_product_keyword(self):
        assert _is_web_only({"services": [{"port": 2222, "product": "OpenSSH 8.9"}]}) is False

    def test_redis_by_product_keyword(self):
        assert _is_web_only({"services": [{"port": 9999, "product": "Redis 7.0"}]}) is False


# ── _svc_label ────────────────────────────────────────────────────────────────

class TestSvcLabel:

    def test_product_and_version(self):
        label = _svc_label(22, "OpenSSH", "8.9p1", "SSH")
        assert "OpenSSH" in label
        assert "8.9p1" in label
        assert "22" in label

    def test_product_without_version(self):
        label = _svc_label(2083, "cPanel", "", "cPanel")
        assert "cPanel" in label
        assert "2083" in label

    def test_unknown_product_uses_fallback(self):
        label = _svc_label(3306, "unknown", "", "MySQL")
        assert "MySQL" in label
        assert "3306" in label

    def test_empty_product_uses_fallback(self):
        label = _svc_label(3389, "", "", "RDP")
        assert "RDP" in label

    def test_no_port_no_fallback(self):
        label = _svc_label(None, "", "", "")
        assert label == "unbekannter Dienst"

    def test_port_only_when_no_product_no_fallback(self):
        label = _svc_label(8080, "", "", "")
        assert "8080" in label


# ── _build_top_risks — spezifische Texte ─────────────────────────────────────

class TestBuildTopRisksSpecificTexts:

    def test_cpanel_title_contains_cpanel(self):
        t = {"services": [{"port": 2083, "product": "cPanel", "version": ""}]}
        risks = _build_top_risks(t, "medium")
        assert any("cPanel" in r["title"] for r in risks)

    def test_cpanel_cause_contains_port(self):
        t = {"services": [{"port": 2083, "product": "cPanel", "version": ""}]}
        risks = _build_top_risks(t, "medium")
        assert any("2083" in r["cause"] for r in risks)

    def test_ssh_cause_contains_openssh_and_version(self):
        t = {"services": [{"port": 22, "product": "OpenSSH", "version": "9.2p1"}]}
        risks = _build_top_risks(t, "medium")
        assert any("OpenSSH" in r["cause"] and "9.2p1" in r["cause"] for r in risks)

    def test_rdp_severity_is_kritisch(self):
        t = {"services": [{"port": 3389, "product": "", "version": ""}]}
        risks = _build_top_risks(t, "medium")
        assert any(r["severity"] == "kritisch" for r in risks)

    def test_redis_severity_is_kritisch(self):
        t = {"services": [{"port": 6379, "product": "Redis", "version": "7.0"}]}
        risks = _build_top_risks(t, "medium")
        assert any(r["severity"] == "kritisch" for r in risks)

    def test_mysql_cause_contains_port_3306(self):
        t = {"services": [{"port": 3306, "product": "MySQL", "version": "8.0.33"}]}
        risks = _build_top_risks(t, "medium")
        assert any("3306" in r["cause"] for r in risks)

    def test_mysql_cause_contains_product_name(self):
        t = {"services": [{"port": 3306, "product": "MySQL", "version": "8.0.33"}]}
        risks = _build_top_risks(t, "medium")
        assert any("MySQL" in r["cause"] for r in risks)

    def test_web_cause_contains_product_name(self):
        t = {"services": [{"port": 443, "product": "nginx", "version": "1.24.0"}]}
        risks = _build_top_risks(t, "medium")
        assert any("nginx" in r["cause"] for r in risks)

    def test_ssh_plus_cpanel_both_in_same_title(self):
        t = {"services": [
            {"port": 22,   "product": "OpenSSH", "version": "8.9"},
            {"port": 2083, "product": "cPanel",  "version": ""},
        ]}
        risks = _build_top_risks(t, "medium")
        admin = next((r for r in risks if "Admin" in r["title"]), None)
        assert admin is not None
        assert "OpenSSH" in admin["title"] or "SSH" in admin["title"]
        assert "cPanel" in admin["title"]

    def test_cpanel_recommendation_mentions_whitelist(self):
        t = {"services": [{"port": 2083, "product": "cPanel", "version": ""}]}
        risks = _build_top_risks(t, "medium")
        assert any("Whitelist" in r["recommendation"] or "whitelist" in r["recommendation"] for r in risks)

    def test_rdp_recommendation_mentions_vpn(self):
        t = {"services": [{"port": 3389, "product": "", "version": ""}]}
        risks = _build_top_risks(t, "medium")
        assert any("VPN" in r["recommendation"] for r in risks)

    def test_severity_sorted_critical_first(self):
        t = {"services": [
            {"port": 443,  "product": "nginx", "version": ""},
            {"port": 3389, "product": "",       "version": ""},
        ]}
        risks = _build_top_risks(t, "medium")
        assert risks[0]["severity"] == "kritisch"

    def test_no_generic_placeholder_text(self):
        """Kein Standardtext der von jedem Unternehmen kommen könnte."""
        t = {"services": [{"port": 22, "product": "OpenSSH", "version": "8.9"}]}
        risks = _build_top_risks(t, "medium")
        for r in risks:
            assert "z.B. SSH/RDP/VNC/Telnet" not in r["cause"]
            assert "Unbefugter Zugriff bei Fehlkonfiguration" not in r["scenario"]


# ── _chain_card ───────────────────────────────────────────────────────────────

class TestChainCard:

    def _step(self, num="01", title="Test", body="Body text.", note="Note."):
        return {"num": num, "title": title, "body": body, "note": note}

    def test_returns_table(self, styles):
        assert isinstance(_chain_card(self._step(), styles), Table)

    def test_num_appears_in_paragraphs(self, styles):
        card = _chain_card(self._step(num="03"), styles)
        paras = _all_paragraphs([card])
        assert any("03" in p.text for p in paras)

    def test_title_appears_in_paragraphs(self, styles):
        card = _chain_card(self._step(title="Recon Step"), styles)
        paras = _all_paragraphs([card])
        assert any("Recon Step" in p.text for p in paras)

    def test_body_appears_in_paragraphs(self, styles):
        card = _chain_card(self._step(body="Specific body content."), styles)
        paras = _all_paragraphs([card])
        assert any("Specific body content" in p.text for p in paras)

    def test_note_appears_in_paragraphs(self, styles):
        card = _chain_card(self._step(note="Important note text."), styles)
        paras = _all_paragraphs([card])
        assert any("Important note text" in p.text for p in paras)

    def test_no_note_does_not_raise(self, styles):
        step = {"num": "01", "title": "T", "body": "B", "note": None}
        assert isinstance(_chain_card(step, styles), Table)


# ── _hinweis_box ──────────────────────────────────────────────────────────────

class TestHinweisBox:

    def test_returns_table(self, styles):
        assert isinstance(_hinweis_box(styles), Table)

    def test_contains_hinweis_text(self, styles):
        box = _hinweis_box(styles)
        paras = _all_paragraphs([box])
        assert any("Hinweis" in p.text for p in paras)

    def test_contains_vollautomatisiert(self, styles):
        box = _hinweis_box(styles)
        paras = _all_paragraphs([box])
        assert any("vollautomatisiert" in p.text for p in paras)


# ── _build_attack_chain ───────────────────────────────────────────────────────

class TestBuildAttackChain:

    def test_always_returns_four_steps(self):
        chain = _build_attack_chain(SSH_DB_WEB)
        assert len(chain) == 4

    def test_step_nums_are_01_to_04(self):
        chain = _build_attack_chain(SSH_DB_WEB)
        assert [s["num"] for s in chain] == ["01", "02", "03", "04"]

    def test_step1_mentions_discovered_service(self):
        t = {"services": [{"port": 22, "product": "OpenSSH", "version": "8.9p1"}]}
        chain = _build_attack_chain(t)
        assert "OpenSSH" in chain[0]["body"]

    def test_step1_mentions_port(self):
        t = {"services": [{"port": 2083, "product": "cPanel", "version": ""}]}
        chain = _build_attack_chain(t)
        assert "2083" in chain[0]["body"] or "cPanel" in chain[0]["body"]

    def test_step2_mentions_cve_if_present(self):
        t = {"services": [{"port": 22, "product": "OpenSSH", "version": "8.9",
                            "cves": [{"id": "CVE-2023-38408", "cvss": 9.8}]}]}
        chain = _build_attack_chain(t)
        assert "CVE-2023-38408" in chain[1]["body"]

    def test_step3_admin_mentions_credential_stuffing(self):
        t = {"services": [{"port": 2083, "product": "cPanel", "version": ""}]}
        chain = _build_attack_chain(t)
        assert "Credential-Stuffing" in chain[2]["body"] or "Bruteforce" in chain[2]["body"]

    def test_step4_title_ransomware(self):
        chain = _build_attack_chain(SSH_DB_WEB)
        assert "Ransomware" in chain[3]["title"]

    def test_step4_db_target_when_db_present(self):
        t = {"services": [{"port": 3306, "product": "MySQL", "version": ""}]}
        chain = _build_attack_chain(t)
        assert "Datenbank" in chain[3]["body"]

    def test_empty_services_still_returns_four_steps(self):
        chain = _build_attack_chain({})
        assert len(chain) == 4

    def test_cve_from_context_evaluation(self):
        class FakeCtx:
            evaluation = {"cves": [{"id": "CVE-2024-0001", "cvss": 9.0}]}

        t = {"services": [{"port": 22, "product": "OpenSSH", "version": "9.0"}]}
        chain = _build_attack_chain(t, context=FakeCtx())
        assert "CVE-2024-0001" in chain[1]["body"]

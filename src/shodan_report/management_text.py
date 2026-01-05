from shodan_report.risk_prioritization import BusinessRisk
from shodan_report.evaluation import Evaluation


def generate_management_text(
    business_risk: BusinessRisk,
    evaluation: Evaluation,
) -> str:
    """
    Erzeugt eine Management-Zusammenfassung für einen Kunden auf Basis des Business-Risikos
    und der Evaluation der AssetSnapshot-Daten.
    """

    # Optional: kritische Punkte dynamisch einfügen
    critical_points_text = ""
    if evaluation.critical_points:
        critical_points_text = "\n\nIdentifizierte kritische Punkte:\n" + "\n".join(
            f"- {pt}" for pt in evaluation.critical_points
        )

    # Texte nach Risiko
    if business_risk == BusinessRisk.MONITOR:
        return (
            f"Gesamteinschätzung:\n"
            f"Die externe Sicherheitslage Ihrer IT-Systeme wird aktuell als stabil bewertet.\n\n"
            f"Es wurden öffentlich erreichbare Dienste identifiziert. Diese erhöhen grundsätzlich "
            f"die Angriffsfläche, zeigen derzeit jedoch keine akuten sicherheitsrelevanten Auffälligkeiten."
            f"{critical_points_text}\n\n"
            f"Empfehlung:\n"
            f"Aktuell besteht kein unmittelbarer Handlungsbedarf. Wir empfehlen, die Situation "
            f"weiterhin regelmäßig zu überwachen."
        )

    if business_risk == BusinessRisk.ATTENTION:
        return (
            f"Gesamteinschätzung:\n"
            f"Die externe Sicherheitslage Ihrer IT-Systeme weist erhöhte Risiken auf.\n\n"
            f"Es wurden mehrere öffentlich erreichbare Dienste festgestellt, die die Angriffsfläche "
            f"vergrößern und intern überprüft werden sollten."
            f"{critical_points_text}\n\n"
            f"Empfehlung:\n"
            f"Wir empfehlen eine Überprüfung durch Ihre IT-Abteilung."
        )

    # Default: CRITICAL
    return (
        f"Gesamteinschätzung:\n"
        f"Die externe Sicherheitslage Ihrer IT-Systeme wird als kritisch eingestuft.\n\n"
        f"Es wurden sicherheitsrelevante Konfigurationen festgestellt, die ein erhöhtes Risiko "
        f"für unbefugte Zugriffe darstellen."
        f"{critical_points_text}\n\n"
        f"Empfehlung:\n"
        f"Wir empfehlen zeitnahes Handeln und eine sofortige technische Bewertung."
    )

from shodan_report.evaluation.models import EvaluationResult
from shodan_report.evaluation.risk_prioritization import BusinessRisk


def generate_management_text(
    business_risk: BusinessRisk,
    evaluation: EvaluationResult,
) -> str:
    # Sicherstellen, dass critical_points existiert und iterierbar ist
    critical_points = getattr(evaluation, "critical_points", [])
    if critical_points is None:
        critical_points = []

    critical_points_text = ""
    if critical_points:
        # Liste alle kritischen Punkte vollständig auf (Tests erwarten vollständige Aufzählung)
        critical_points_text = "\n\nIdentifizierte kritische Punkte:\n" + "\n".join(
            f"- {pt}" for pt in critical_points
        )

    print(f"DEBUG - EvaluationResult Type: {type(evaluation)}")
    print(f"DEBUG - Has critical_points: {hasattr(evaluation, 'critical_points')}")
    print(
        f"DEBUG - critical_points: {evaluation.critical_points if hasattr(evaluation, 'critical_points') else 'N/A'}"
    )
    print(
        f"DEBUG - critical_points count: {len(evaluation.critical_points) if hasattr(evaluation, 'critical_points') else 0}"
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

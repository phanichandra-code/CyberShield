from database_manager import save_alert


def generate_alert(
    alert_type,
    ip,
    details,
    severity
):

    print("\n🚨 SECURITY ALERT 🚨")

    print(
        "Alert Type:",
        alert_type
    )

    print(
        "IP Address:",
        ip
    )

    print(
        "Severity:",
        severity
    )

    print(
        "Details:",
        details
    )

    print(
        "-------------------------"
    )


    save_alert(
        alert_type,
        ip,
        details,
        severity
    )
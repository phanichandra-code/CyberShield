import streamlit as st
import os
import mysql.connector
from dotenv import load_dotenv
from collections import Counter


# ==========================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="CyberShield SOC",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_database_connection():

    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )


# ==========================================
# HEADER
# ==========================================

st.title("🛡️ CyberShield SOC")

st.subheader(
    "Network Security Monitoring & Threat Detection System"
)

st.caption(
    "Security Operations Center Dashboard | "
    "Simulated Security Events"
)


# ==========================================
# REFRESH BUTTON
# ==========================================

if st.button("🔄 Refresh Dashboard"):

    st.rerun()


st.divider()


# ==========================================
# DATABASE OPERATIONS
# ==========================================

try:

    connection = get_database_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            alert_id,
            alert_type,
            ip_address,
            details,
            severity,
            detected_at
        FROM alerts
        ORDER BY detected_at DESC
    """)

    alerts = cursor.fetchall()

    cursor.close()
    connection.close()


    # ======================================
    # DATABASE STATUS
    # ======================================

    st.success(
        "🟢 Database connected successfully"
    )


    # ======================================
    # SECURITY OVERVIEW
    # ======================================

    st.header("📊 Security Overview")


    total_alerts = len(alerts)


    high_alerts = sum(
        1
        for alert in alerts
        if alert[4] == "High"
    )


    medium_alerts = sum(
        1
        for alert in alerts
        if alert[4] == "Medium"
    )


    unique_ips = len(
        set(
            alert[2]
            for alert in alerts
        )
    )


    # ======================================
    # OVERVIEW METRICS
    # ======================================

    col1, col2, col3, col4 = st.columns(4)


    with col1:

        st.metric(
            "🚨 Total Alerts",
            total_alerts
        )


    with col2:

        st.metric(
            "🔴 High Severity",
            high_alerts
        )


    with col3:

        st.metric(
            "🟠 Medium Severity",
            medium_alerts
        )


    with col4:

        st.metric(
            "🌐 Unique IPs",
            unique_ips
        )


    st.divider()


    # ======================================
    # ALERT FILTERS
    # ======================================

    st.header("🔍 Alert Filters")


    col1, col2 = st.columns(2)


    with col1:

        alert_type_options = [
            "All Alerts",
            "Brute Force",
            "Port Scan",
            "High-Volume Activity"
        ]


        selected_alert_type = st.selectbox(
            "Alert Type",
            alert_type_options
        )


    with col2:

        severity_options = [
            "All Severities",
            "High",
            "Medium"
        ]


        selected_severity = st.selectbox(
            "Severity",
            severity_options
        )


    # ======================================
    # APPLY FILTERS
    # ======================================

    filtered_alerts = alerts


    if selected_alert_type != "All Alerts":

        filtered_alerts = [
            alert
            for alert in filtered_alerts
            if alert[1] == selected_alert_type
        ]


    if selected_severity != "All Severities":

        filtered_alerts = [
            alert
            for alert in filtered_alerts
            if alert[4] == selected_severity
        ]


    st.divider()


    # ======================================
    # ALERT DISTRIBUTION
    # ======================================

    st.header("📈 Alert Distribution")


    alert_counts = Counter(
        alert[1]
        for alert in filtered_alerts
    )


    if alert_counts:

        col1, col2, col3 = st.columns(3)


        with col1:

            st.metric(
                "🔐 Brute Force",
                alert_counts.get(
                    "Brute Force",
                    0
                )
            )


        with col2:

            st.metric(
                "🔎 Port Scan",
                alert_counts.get(
                    "Port Scan",
                    0
                )
            )


        with col3:

            st.metric(
                "📡 High-Volume",
                alert_counts.get(
                    "High-Volume Activity",
                    0
                )
            )


    else:

        st.info(
            "No alerts match the selected filters."
        )


    st.divider()


    # ======================================
    # SOURCE IP ANALYTICS
    # ======================================

    st.header("🌐 Source IP Analytics")


    ip_counts = Counter(
        alert[2]
        for alert in filtered_alerts
    )


    if ip_counts:

        st.write(
            "Number of security alerts generated "
            "by each source IP address:"
        )


        for ip_address, count in ip_counts.items():

            st.write(
                f"**{ip_address}** → "
                f"{count} alert(s)"
            )


    else:

        st.info(
            "No IP activity available."
        )


    st.divider()


    # ======================================
    # SEVERITY DISTRIBUTION
    # ======================================

    st.header("⚠️ Severity Distribution")


    severity_counts = Counter(
        alert[4]
        for alert in filtered_alerts
    )


    if severity_counts:

        col1, col2 = st.columns(2)


        with col1:

            st.metric(
                "🔴 High Severity",
                severity_counts.get(
                    "High",
                    0
                )
            )


        with col2:

            st.metric(
                "🟠 Medium Severity",
                severity_counts.get(
                    "Medium",
                    0
                )
            )


    else:

        st.info(
            "No severity data available."
        )


    st.divider()


    # ======================================
    # SECURITY ALERTS
    # ======================================

    st.header("🚨 Security Alerts")


    if filtered_alerts:

        table_data = []


        for alert in filtered_alerts:

            severity = alert[4]


            if severity == "High":

                severity_display = "🔴 High"

            elif severity == "Medium":

                severity_display = "🟠 Medium"

            else:

                severity_display = severity


            table_data.append({

                "ID": alert[0],

                "Alert Type": alert[1],

                "IP Address": alert[2],

                "Severity": severity_display,

                "Details": alert[3],

                "Detected At": alert[5]

            })


        # Static table to avoid dataframe
        # rendering artifacts

        st.table(table_data)


        st.caption(
            f"Showing {len(filtered_alerts)} alert(s)"
        )


    else:

        st.info(
            "No security alerts found."
        )


    st.divider()


    # ======================================
    # RECENT SECURITY ACTIVITY
    # ======================================

    st.header("🕒 Recent Security Activity")


    if filtered_alerts:

        recent_alerts = filtered_alerts[:5]


        for alert in recent_alerts:

            alert_id = alert[0]

            alert_type = alert[1]

            ip_address = alert[2]

            details = alert[3]

            severity = alert[4]

            detected_at = alert[5]


            if severity == "High":

                icon = "🔴"

            elif severity == "Medium":

                icon = "🟠"

            else:

                icon = "⚪"


            with st.expander(
                f"{icon} {alert_type} | "
                f"{ip_address} | "
                f"{severity}"
            ):

                col1, col2 = st.columns(2)


                with col1:

                    st.write(
                        f"**Alert ID:** {alert_id}"
                    )

                    st.write(
                        f"**Alert Type:** {alert_type}"
                    )

                    st.write(
                        f"**IP Address:** {ip_address}"
                    )


                with col2:

                    st.write(
                        f"**Severity:** {severity}"
                    )

                    st.write(
                        f"**Detected At:** {detected_at}"
                    )


                st.write(
                    f"**Details:** {details}"
                )


    else:

        st.info(
            "No recent security activity."
        )


# ==========================================
# ERROR HANDLING
# ==========================================

except Exception as e:

    st.error(
        "❌ Unable to connect to the "
        "CyberShield database."
    )

    st.write(
        "Error details:",
        str(e)
    )
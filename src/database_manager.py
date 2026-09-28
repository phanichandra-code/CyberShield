import os

import mysql.connector

from dotenv import load_dotenv


load_dotenv()


def save_alert(
    alert_type,
    ip,
    details,
    severity
):

    connection = mysql.connector.connect(

        host=os.getenv("DB_HOST"),

        user=os.getenv("DB_USER"),

        password=os.getenv("DB_PASSWORD"),

        database=os.getenv("DB_NAME")
    )


    cursor = connection.cursor()


    # ======================================
    # CHECK FOR RECENT DUPLICATE
    # ======================================

    check_query = """

    SELECT alert_id

    FROM alerts

    WHERE alert_type = %s

    AND ip_address = %s

    AND details = %s

    AND detected_at >= NOW() - INTERVAL 60 SECOND

    LIMIT 1

    """


    check_values = (

        alert_type,

        ip,

        details
    )


    cursor.execute(
        check_query,
        check_values
    )


    existing_alert = cursor.fetchone()


    # ======================================
    # SAVE NEW ALERT
    # ======================================

    if existing_alert is None:

        insert_query = """

        INSERT INTO alerts
        (
            alert_type,
            ip_address,
            details,
            severity,
            detected_at
        )

        VALUES
        (
            %s,
            %s,
            %s,
            %s,
            NOW()
        )

        """


        insert_values = (

            alert_type,

            ip,

            details,

            severity
        )


        cursor.execute(
            insert_query,
            insert_values
        )


        connection.commit()


        print(
            "✅ Alert saved to database."
        )


    else:

        print(
            "ℹ️ Duplicate alert skipped "
            "(detected within the last 60 seconds)."
        )


    cursor.close()

    connection.close()
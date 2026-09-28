from datetime import datetime
from alert_manager import generate_alert


def detect_port_scan(file_path="logs/security.log"):

    port_activity = {}


    with open(file_path, "r") as file:

        for line in file:

            if not line.strip():
                continue


            parts = line.strip().split("|")


            timestamp = parts[0].strip()

            ip = parts[1].strip()

            event = parts[2].strip()

            port = parts[3].strip()


            if event == "PORT_ACCESS":

                time = datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )


                if ip not in port_activity:

                    port_activity[ip] = []


                port_activity[ip].append(
                    (time, port)
                )


    port_threshold = 5

    time_window = 60


    for ip, activities in port_activity.items():

        activities.sort()


        # Sliding window detection

        for i in range(len(activities)):

            window_start = activities[i][0]

            unique_ports = set()


            for j in range(
                i,
                len(activities)
            ):

                current_time = activities[j][0]

                current_port = activities[j][1]


                time_difference = (
                    current_time - window_start
                ).total_seconds()


                if time_difference <= time_window:

                    unique_ports.add(
                        current_port
                    )

                else:

                    break


                # Threshold reached

                if len(unique_ports) >= port_threshold:

                    generate_alert(
                        "Port Scan",
                        ip,
                        f"{len(unique_ports)} different ports "
                        f"accessed within {time_difference} seconds",
                        "Medium"
                    )

                    break


            if len(unique_ports) >= port_threshold:

                break
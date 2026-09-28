from datetime import datetime
from alert_manager import generate_alert


def detect_high_volume(file_path="logs/security.log"):

    request_activity = {}


    with open(file_path, "r") as file:

        for line in file:

            if not line.strip():
                continue


            parts = line.strip().split("|")


            timestamp = parts[0].strip()

            ip = parts[1].strip()

            event = parts[2].strip()


            if event == "REQUEST":

                time = datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )


                if ip not in request_activity:

                    request_activity[ip] = []


                request_activity[ip].append(time)


    request_threshold = 10

    time_window = 60


    for ip, timestamps in request_activity.items():

        timestamps.sort()


        # Sliding window detection

        for i in range(len(timestamps)):

            window_start = timestamps[i]

            requests_in_window = 1


            for j in range(
                i + 1,
                len(timestamps)
            ):

                time_difference = (
                    timestamps[j] - window_start
                ).total_seconds()


                if time_difference <= time_window:

                    requests_in_window += 1

                else:

                    break


            if requests_in_window >= request_threshold:

                window_end = timestamps[
                    i + requests_in_window - 1
                ]


                time_difference = (
                    window_end - window_start
                ).total_seconds()


                generate_alert(
                    "High-Volume Activity",
                    ip,
                    f"{requests_in_window} requests "
                    f"within {time_difference} seconds",
                    "High"
                )


                break
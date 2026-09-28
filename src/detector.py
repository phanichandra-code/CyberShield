from datetime import datetime
from alert_manager import generate_alert


def detect_brute_force(file_path="logs/security.log"):

    failed_attempts = {}


    with open(file_path, "r") as file:

        for line in file:

            if not line.strip():
                continue


            parts = line.strip().split("|")


            timestamp = parts[0].strip()

            ip = parts[1].strip()

            event = parts[2].strip()


            if event == "LOGIN_FAILED":

                time = datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )


                if ip not in failed_attempts:

                    failed_attempts[ip] = []


                failed_attempts[ip].append(time)


    threshold = 5

    time_window = 60


    for ip, timestamps in failed_attempts.items():

        timestamps.sort()


        # Sliding window detection

        for i in range(len(timestamps)):

            window_start = timestamps[i]

            attempts_in_window = 1


            for j in range(
                i + 1,
                len(timestamps)
            ):

                time_difference = (
                    timestamps[j] - window_start
                ).total_seconds()


                if time_difference <= time_window:

                    attempts_in_window += 1

                else:

                    break


            if attempts_in_window >= threshold:

                window_end = timestamps[
                    i + attempts_in_window - 1
                ]


                time_difference = (
                    window_end - window_start
                ).total_seconds()


                generate_alert(
                    "Brute Force",
                    ip,
                    f"{attempts_in_window} failed login attempts "
                    f"within {time_difference} seconds",
                    "High"
                )


                break
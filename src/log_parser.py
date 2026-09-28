file_path = "logs/security.log"


with open(file_path, "r") as file:

    for line in file:

        if not line.strip():
            continue

        parts = line.strip().split("|")

        log_data = {

            "timestamp": parts[0].strip(),

            "ip": parts[1].strip(),

            "event": parts[2].strip(),

            "username": parts[3].strip()

        }

        print(log_data)
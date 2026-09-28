from detector import detect_brute_force

from port_scan_detector import detect_port_scan

from dos_detector import detect_high_volume


print("================================")

print(
    "      CYBERSHIELD STARTING"
)

print("================================")


# ======================================
# BRUTE FORCE
# ======================================

print(
    "\n[1] Checking for brute-force activity..."
)

detect_brute_force()


# ======================================
# PORT SCAN
# ======================================

print(
    "\n[2] Checking for port-scan activity..."
)

detect_port_scan()


# ======================================
# HIGH VOLUME
# ======================================

print(
    "\n[3] Checking for high-volume activity..."
)

detect_high_volume()


print("\n================================")

print(
    "      CYBERSHIELD FINISHED"
)

print("================================")
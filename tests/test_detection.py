import sys

import os

import io

from contextlib import redirect_stdout


# ==========================================
# IMPORT PROJECT MODULES
# ==========================================

sys.path.append(

    os.path.abspath(

        os.path.join(

            os.path.dirname(__file__),

            "..",

            "src"

        )

    )

)


from detector import detect_brute_force

from port_scan_detector import detect_port_scan

from dos_detector import detect_high_volume


# ==========================================
# TEST LOG
# ==========================================

test_log = "tests/test_security.log"


# ==========================================
# TEST COUNTERS
# ==========================================

passed = 0

failed = 0


# ==========================================
# POSITIVE TEST
# ==========================================

def positive_test(

    test_name,

    detector_function,

    expected_ip

):

    global passed

    global failed


    print(
        f"\n[{test_name}]"
    )


    output = io.StringIO()


    try:

        with redirect_stdout(output):

            detector_function(test_log)


        result = output.getvalue()


        if expected_ip in result:

            print("PASS ✅")

            print(

                f"Alert correctly detected "
                f"for {expected_ip}"

            )

            passed += 1

        else:

            print("FAIL ❌")

            print(

                f"Expected alert for "
                f"{expected_ip} was not detected."

            )

            failed += 1


    except Exception as e:

        print("FAIL ❌")

        print("Error:", e)

        failed += 1


# ==========================================
# NEGATIVE TEST
# ==========================================

def negative_test(

    test_name,

    detector_function,

    unexpected_ip

):

    global passed

    global failed


    print(
        f"\n[{test_name}]"
    )


    output = io.StringIO()


    try:

        with redirect_stdout(output):

            detector_function(test_log)


        result = output.getvalue()


        if unexpected_ip not in result:

            print("PASS ✅")

            print(

                f"No false alert generated "
                f"for {unexpected_ip}"

            )

            passed += 1

        else:

            print("FAIL ❌")

            print(

                f"False alert generated "
                f"for {unexpected_ip}"

            )

            failed += 1


    except Exception as e:

        print("FAIL ❌")

        print("Error:", e)

        failed += 1


# ==========================================
# START TESTING
# ==========================================

print("======================================")

print(
    "       CYBERSHIELD SECURITY TESTS"
)

print("======================================")


# ==========================================
# POSITIVE TESTS
# ==========================================

positive_test(

    "TEST 1 - Brute Force Detection",

    detect_brute_force,

    "10.0.0.10"

)


positive_test(

    "TEST 2 - Port Scan Detection",

    detect_port_scan,

    "10.0.0.30"

)


positive_test(

    "TEST 3 - High Volume Detection",

    detect_high_volume,

    "10.0.0.50"

)


# ==========================================
# NEGATIVE TESTS
# ==========================================

negative_test(

    "TEST 4 - Normal Login Activity",

    detect_brute_force,

    "10.0.0.20"

)


negative_test(

    "TEST 5 - Normal Port Activity",

    detect_port_scan,

    "10.0.0.40"

)


negative_test(

    "TEST 6 - Normal Request Activity",

    detect_high_volume,

    "10.0.0.60"

)
negative_test(
    "TEST 7 - Brute Force Boundary",
    detect_brute_force,
    "10.0.0.70"
)

negative_test(
    "TEST 8 - Port Scan Boundary",
    detect_port_scan,
    "10.0.0.80"
)

negative_test(
    "TEST 9 - High Volume Boundary",
    detect_high_volume,
    "10.0.0.90"
)

# ==========================================
# FINAL SUMMARY
# ==========================================

print("\n======================================")

print(
    "           TEST SUMMARY"
)

print("======================================")


print(
    "Tests Passed :",
    passed
)


print(
    "Tests Failed :",
    failed
)


total_tests = passed + failed


print(
    "Total Tests  :",
    total_tests
)


if failed == 0:

    print(
        "\n🎉 ALL TESTS PASSED!"
    )

else:

    print(
        "\n⚠️ SOME TESTS FAILED."
    )


print(
    "======================================"
)
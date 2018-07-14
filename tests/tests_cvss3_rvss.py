from cvsslib.vector import calculate_vector
from cvsslib import RVSSState, CVSS3State, rvss, cvss3
from cvsslib.utils import get_enums
# from cvsslib.example_vectors import v3_vectors, rvss_vectors, rvss_comparison_vectors

rvss_comparison_vectors = [
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N",
        "RVSS:1.0/AV:L/AC:L/PR:H/UI:R/Y:U/S:U/C:H/I:N/A:H/H:N/MPR:N",
        (5.8, 5.8, 7.1)),
]

analysis_vectors = [
    ("Missing authentication mechanisms in Robotis RoboPlus protocol allow remote attackers to unauthorizedly control the robot via network communication.",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "RVSS:1.0/AV:ANPR/AC:L/PR:N/UI:N/Y:T/S:U/C:N/I:H/A:H/H:E"),
    ("An attacker on an adjacent network could perform command injection.",
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "RVSS:1.0/AV:AN/AC:L/PR:N/UI:N/Y:O/S:U/C:H/I:H/A:H/H:E"),
    ("An stack-based buffer overflow in Universal Robots Modbus TCP service could allow remote attackers to execute arbitrary code and alter protected settings via specially crafted packets.",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "RVSS:1.0/AV:AN/AC:L/PR:N/UI:N/Y:T/S:C/C:H/I:H/A:H/H:H",
    ),
]

def comparison_rvss_vectors():
    for vector1, vector2, results in rvss_comparison_vectors:
        score1 = calculate_vector(vector1, cvss3)
        score2 = calculate_vector(vector2, rvss)
        # print(score)
        # print(results)
        assert results == score1, "Vector {0} failed".format(vector1)
        assert results == score2, "Vector {0} failed".format(vector2)
        assert score1 == score2, "CVSS and RVSS vectors' score don't match "

def analysis_cvss3_rvss_vector():
    for description, vector_cvss3, vector_rvss in analysis_vectors:
        score_cvss3 = calculate_vector(vector_cvss3, cvss3)
        score_rvss = calculate_vector(vector_rvss, rvss)
        print("---------------------------------------------------------------")
        print(description)
        print("CVSSv3: ",score_cvss3)
        print("RVSSv1: ",score_rvss)


## Run tests
comparison_rvss_vectors()
analysis_cvss3_rvss_vector()

###########
## Individual tests
###########

# vector_v3 = "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N"
# print(calculate_vector(vector_v3, cvss3))

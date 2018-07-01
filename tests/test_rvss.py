from cvsslib.vector import calculate_vector
from cvsslib import RVSSState, CVSS3State, rvss, cvss3
from cvsslib.utils import get_enums
# from cvsslib.example_vectors import v3_vectors, rvss_vectors, rvss_comparison_vectors

# TODO: bring this vector to "example_vectors.py" file
rvss_vectors = [
    # Various tests for the attack vector (AV)
    ("RVSS:1.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.8, 5.8, 7.1)),
    ("RVSS:1.0/AV:RN/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (6.1, 6.1, 8.1)),
    ("RVSS:1.0/AV:AN/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.9, 5.9, 7.3)),
    ("RVSS:1.0/AV:PP/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.9, 5.9, 7.3)),
    ("RVSS:1.0/AV:PI/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.4, 5.4, 5.9)),
    # AV combinations
    ("RVSS:1.0/AV:ANPR/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.5, 5.5, 6.1)),
    ("RVSS:1.0/AV:PPL/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.6, 5.6, 6.4)),
]

def test_v3_vectors():
    for vector, results in v3_vectors:
        score = calculate_vector(vector, cvss3)
        # print(score)
        # print(results)
        assert results == score, "Vector {0} failed".format(vector)

def test_rvss_vectors():
    for vector, results in rvss_vectors:
        score = calculate_vector(vector, rvss)
        # print(score)
        # print(results)
        assert results == score, "Vector {0} failed".format(vector)


# test_v3_vectors()
# test_rvss_vectors()

###########
## Individual tests
###########

# vector_v3 = "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N"
# print(calculate_vector(vector_v3, cvss3))

from cvsslib import cvss2, cvss3, rvss, calculate_vector

# vector_v2 = "AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N"
# "AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H"
vector = "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N"

# print(calculate_vector(vector_v2, cvss2))
vector_v3 = "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N"
# print("base_score, temporal_score and environment_score: "+str(calculate_vector(vector, cvss3)))
print("base_score, temporal_score and environment_score: "+str(calculate_vector(vector, rvss)))

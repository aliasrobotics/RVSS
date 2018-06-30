v3_vectors = [
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", (4.6, 4.6, 0.0)),
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:L/MI:N/MA:N", (4.6, 4.6, 4.3)),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:U/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:L", (5.8, 5.2, 7.4)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", (0.0, 0.0, 0.0)),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.8, 5.8, 7.1)),
    ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H", (8.2, 8.2, 8.2)),
    ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L/E:U/RL:U/RC:R/CR:M/MPR:L/MUI:R/MI:N/MA:H", (7.7, 6.8, 6.3)),
    ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N/E:P/RL:U/RC:U/CR:H/IR:L/AR:H/MAV:L/MUI:R/MS:C/MC:N/MI:L/MA:N", (5.3, 4.6, 1.3)),

    # Taken from the CVSS examples page: https://www.first.org/cvss/examples
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", (6.1, 6.1, 6.1)),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", (6.4, 6.4, 6.4)),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", (3.1, 3.1, 3.1)),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", (9.9, 9.9, 9.9)),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", (4.2, 4.2, 4.2)),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", (8.8, 8.8, 8.8)),
    ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", (7.8, 7.8, 7.8)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", (7.5, 7.5, 7.5)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", (9.8, 9.8, 9.8)),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", (6.8, 6.8, 6.8)),
    ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", (6.8, 6.8, 6.8)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", (5.8, 5.8, 5.8)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", (5.8, 5.8, 5.8)),
    ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", (9.3, 9.3, 9.3)),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", (5.4, 5.4, 5.4)),
    ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", (7.8, 7.8, 7.8)),
    ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", (8.8, 8.8, 8.8)),
    ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", (4.6, 4.6, 4.6)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", (8.8, 8.8, 8.8)),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", (7.4, 7.4, 7.4)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", (9.6, 9.6, 9.6))
]


v2_vectors = [
    ("AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H", (5, 3.5, 1.2)),
    ("AV:N/AC:M/Au:M/C:C/I:N/A:P/RL:W/RC:UC/CDP:LM/TD:M/CR:L/IR:L/AR:L", (6.4, 5.5, 4)),
    ("AV:L/AC:L/Au:S/C:P/I:P/A:P/E:U/RC:C/CDP:LM/TD:L/IR:H/AR:M", (4.3, 3.7, 1.5)),
    ("AV:A/AC:M/Au:S/C:C/I:P/A:C", (7, None, None)),

    # From the example document
    ("AV:N/AC:M/Au:N/C:N/I:P/A:N", (4.3, None, None)),
    ("AV:N/AC:L/Au:S/C:P/I:P/A:N", (5.5, None, None)),
    ("AV:N/AC:M/Au:N/C:P/I:N/A:N", (4.3, None, None)),
    ("AV:N/AC:L/Au:S/C:C/I:C/A:C", (9, None, None)),
    ("AV:L/AC:L/Au:N/C:P/I:P/A:P", (4.6, None, None)),
    ("AV:N/AC:M/Au:S/C:C/I:C/A:C", (8.5, None, None)),
    ("AV:N/AC:M/Au:N/C:P/I:P/A:P", (6.8, None, None)),
    ("AV:N/AC:L/Au:N/C:P/I:N/A:N", (5, None, None)),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", (10, None, None)),
    ("AV:N/AC:L/Au:N/C:N/I:P/A:N", (5, None, None)),
    ("AV:L/AC:M/Au:N/C:C/I:C/A:C", (6.9, None, None)),
    ("AV:N/AC:L/Au:N/C:P/I:N/A:N", (5, None, None)),
    ("AV:N/AC:L/Au:N/C:N/I:P/A:N", (5, None, None)),
    ("AV:A/AC:L/Au:N/C:N/I:C/A:N", (6.1, None, None)),
    ("AV:N/AC:M/Au:N/C:N/I:P/A:N", (4.3, None, None)),
    ("AV:N/AC:M/Au:N/C:C/I:C/A:C", (9.3, None, None)),
    ("AV:A/AC:L/Au:N/C:C/I:C/A:C", (8.3, None, None)),
    ("AV:L/AC:L/Au:N/C:N/I:C/A:N", (4.9, None, None)),
    ("AV:N/AC:M/Au:N/C:P/I:P/A:P", (6.8, None, None)),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", (10, None, None))
]

rvss_vectors = [
    ("RVSS:1.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.8, 5.8, 7.1)),
    # ("RVSS:1.0/AV:RN/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.8, 5.8, 7.1)),
]

rvss_comparison_vectors = [
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", "AV:N/AC:L/Au:N/C:C/I:C/A:C", (10, None, None))
]

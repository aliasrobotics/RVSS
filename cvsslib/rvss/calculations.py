import math

from .enums import *
from decimal import Decimal as D
from cvsslib.base_enum import NotDefined
import decimal

EXPLOITABILITY_COEFFECIENT = D("8.22")
IMPACT_UNCHANGED_COEFFECIENT = D("6.42")
IMPACT_CHANGED_COEFFECIENT = D("7.52")


def roundup(num):
    return D(math.ceil(num * 10) / 10).quantize(D("0.1"))


def calculate_exploitability_sub_score(attack_vector: AttackVector,
                                       complexity: AttackComplexity,
                                       privilege: PrivilegeRequired,
                                       interaction: UserInteraction,
                                       age:Age):
    # print("age: " + str(age))
    return EXPLOITABILITY_COEFFECIENT * attack_vector * complexity * privilege * interaction * age

def calculate_modified_exploitability_sub_score(vector: ModifiedAttackVector,
                                                complexity: ModifiedAttackComplexity,
                                                privilege: ModifiedPrivilegesRequired,
                                                interaction: ModifiedUserInteraction,
                                                age: ModifiedAge):
    # print("modified complexity: " + str(complexity))
    # print("modified privilege: " + str(privilege))
    # print("modified interaction: " + str(interaction))
    # print("modified age: " + str(age))
    return EXPLOITABILITY_COEFFECIENT * vector * complexity * privilege * interaction * age


def calculate_impact_sub_score(scope: Scope,
                               conf_impact: ConfidentialityImpact,
                               integ_impact: IntegrityImpact,
                               avail_impact: AvailabilityImpact,
                               safe_impact: SafetyImpact):


    safety_weight = decimal.Decimal(1.2)
    # safety setup 2
    base_impact_sub_score = 1 - ((1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact)) \
        + safety_weight * safe_impact

    # base_impact_sub_score_old = 1 - ((1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact))

    # print("actual: ", base_impact_sub_score)
    # print("old: ", base_impact_sub_score_old)

    # # safety setup 1
    # base_impact_sub_score = safety_weight * safe_impact - ((1 - conf_impact) * (1 - integ_impact)
    #                         * (1 - avail_impact))

    if scope == Scope.UNCHANGED.value:
        # print("actual final: ", IMPACT_UNCHANGED_COEFFECIENT * base_impact_sub_score)
        # print("old final: ",IMPACT_UNCHANGED_COEFFECIENT * base_impact_sub_score_old)
        return IMPACT_UNCHANGED_COEFFECIENT * base_impact_sub_score
    else:
        if base_impact_sub_score > 1.0:
            base_impact_sub_score = D(1.0) # trim the base_impact_sub_score
            # Slighly modify the math so that it still rates as before
            changed_value = IMPACT_CHANGED_COEFFECIENT *\
                   (base_impact_sub_score - D("0.029")) -\
                   D("3.25") * D(math.pow(base_impact_sub_score - D("0.04"), 15))
            # print("changed_value: ", changed_value)
            return changed_value

        else:
            changed_value = IMPACT_CHANGED_COEFFECIENT *\
                   (base_impact_sub_score - D("0.029")) -\
                   D("3.25") * D(math.pow(base_impact_sub_score - D("0.02"), 15))
            # print("changed_value: ", changed_value)
            return changed_value


def calculate_modified_impact_sub_score(scope: ModifiedScope,
                                        modified_conf: ModifiedConfidentialityImpact,
                                        modified_integ: ModifiedIntegrityImpact,
                                        modified_avail: ModifiedAvailabilityImpact,
                                        modified_safe: ModifiedSafetyImpact,
                                        conf_req: ConfidentialityRequirement,
                                        integ_req: IntegrityRequirement,
                                        avail_req: AvailabilityRequirement,
                                        safe_req: SafetyRequirement):
    # print(modified_safe)
    # print(safe_req)

    safety_weight = decimal.Decimal(1.2)
    # safety setup 2
    modified = min(
        1 -
        (1 - modified_conf * conf_req) *
        (1 - modified_integ * integ_req) *
        (1 - modified_avail * avail_req),
        0.915) + safety_weight * modified_safe * safe_req

    # # safety setup 1
    # modified = safety_weight * modified_safe * safe_req - (1 - modified_conf * conf_req) \
    #     * (1 - modified_integ * integ_req) * (1 - modified_avail * avail_req)


    if scope == ModifiedScope.UNCHANGED.value:
        # print("calculating")
        # print(type(IMPACT_UNCHANGED_COEFFECIENT)) # Decimal.decimal
        # print(type(modified)) # float
        # print(IMPACT_UNCHANGED_COEFFECIENT * decimal.Decimal(modified))
        return IMPACT_UNCHANGED_COEFFECIENT * decimal.Decimal(modified)
    else:
        if modified > 1.0:
            modified = D(1.0) # trim the modified value
            return IMPACT_CHANGED_COEFFECIENT * (decimal.Decimal(modified) - \
                D("0.029")) - D("3.25") * \
                D(math.pow(decimal.Decimal(modified) - D(0.04), 15))
        else:
            return IMPACT_CHANGED_COEFFECIENT * (decimal.Decimal(modified) - \
                D("0.029")) - D("3.25") * \
                D(math.pow(decimal.Decimal(modified) - D(0.02), 15))


def calculate_base_score(run_calculation, scope: Scope, privilege: PrivilegeRequired):
    impact_sub_score = run_calculation(calculate_impact_sub_score)

    if impact_sub_score <= 0:
        return 0
    else:

        override = {}
        if scope == Scope.CHANGED.value:
            # Ok, so the privilege enum needs slightly different values depending on the scope. God damn.
            modified_privilege = PrivilegeRequired.extend("PrivilegeRequired", {"LOW": D("0.68"), "HIGH": D("0.50")})
            privilege = getattr(modified_privilege, PrivilegeRequired(privilege).name)
            override[PrivilegeRequired] = privilege.value

        exploitability_sub_score = run_calculation(calculate_exploitability_sub_score, override=override)

        combined_score = impact_sub_score + exploitability_sub_score

        if scope == Scope.CHANGED.value:
            return roundup(min(D("1.08") * combined_score, 10))
        else:
            return roundup(min(combined_score, 10))


def calculate_temporal_score(base_score,
                             maturity: ExploitCodeMaturity,
                             remediation: RemediationLevel,
                             confidence: ReportConfidence):
    return roundup(base_score * maturity * remediation * confidence)


def calculate_environmental_score(run_calculation,
                                  modified_scope: ModifiedScope,
                                  exploit_code: ExploitCodeMaturity,
                                  remediation: RemediationLevel,
                                  confidence: ReportConfidence,
                                  privilege: ModifiedPrivilegesRequired):

    modified_impact_sub_score = run_calculation(calculate_modified_impact_sub_score)
    # print(modified_impact_sub_score)

    if modified_impact_sub_score <= 0:
        return 0

    if modified_scope == ModifiedScope.CHANGED.value:
        # Ok, so the privilege enum needs slightly different values depending on the scope. God damn.
        modified_privilege = ModifiedPrivilegesRequired.extend("ModifiedPrivilegeRequired", {"LOW": D("0.68"), "HIGH": D("0.50")})
        privilege = getattr(modified_privilege, ModifiedPrivilegesRequired(privilege).name).value

    modified_exploitability_sub_score = run_calculation(calculate_modified_exploitability_sub_score,
                                                        override={ModifiedPrivilegesRequired: privilege})

    if modified_scope == ModifiedScope.UNCHANGED.value:
        return roundup(
            roundup(min(modified_impact_sub_score + modified_exploitability_sub_score, 10)) *
            exploit_code * remediation * confidence
        )
    else:
        return roundup(
            roundup(min(D("1.08") * (modified_impact_sub_score + modified_exploitability_sub_score), 10)) *
            exploit_code * remediation * confidence
        )


def calculate(run_calculation, get):
    base_score = run_calculation(calculate_base_score)
    temporal_score = run_calculation(calculate_temporal_score, base_score)

    override = {}

    for optional_enum in OPTIONAL_VALUES:
        set_value = get(optional_enum)

        if isinstance(set_value.value, NotDefined):
            # Override the value with the non-optional one
            parent_enum_class = optional_enum._parent
            parent_enum_value = get(parent_enum_class)
            override[optional_enum] = parent_enum_value.value

    environment_score = run_calculation(calculate_environmental_score, override=override)

    return float(base_score), float(temporal_score), float(environment_score)

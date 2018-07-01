from decimal import Decimal as D

from cvsslib.base_enum import BaseEnum, NotDefined


# Taken from https://www.first.org/cvss/specification-document#i8.4

# Exploitability metrics
class AttackVector(BaseEnum):
    """
    Vector: AV
    Mandatory: yes
    """
    # NETWORK = D("0.85")
    # ADJACENT_NETWORK = D("0.62")
    # LOCAL = D("0.55")
    # PHYSICAL = D("0.2")
    REMOTE_NETWORK = D("0.85")
    ADJACENT_NETWORK = D("0.62")
    INTERNAL_NETWORK = D("0.4")
    LOCAL = D("0.55")
    PHYSICAL_PUBLIC = D("0.62")
    PHYSICAL_RESTRICTED = D("0.4")
    PHYSICAL_ISOLATED = D("0.2")
    # combinations
    # REMOTE_NETWORK_AND_PHYSICAL_PUBLIC = D("0.85")*D("0.62")
    REMOTE_NETWORK_AND_PHYSICAL_PUBLIC = REMOTE_NETWORK * PHYSICAL_PUBLIC
    REMOTE_NETWORK_AND_PHYSICAL_RESTRICTED = REMOTE_NETWORK * PHYSICAL_RESTRICTED
    REMOTE_NETWORK_AND_PHYSICAL_ISOLATED = REMOTE_NETWORK * PHYSICAL_ISOLATED

    ADJACENT_NETWORK_AND_PHYSICAL_PUBLIC = ADJACENT_NETWORK * PHYSICAL_PUBLIC
    ADJACENT_NETWORK_AND_PHYSICAL_RESTRICTED = ADJACENT_NETWORK * PHYSICAL_RESTRICTED
    ADJACENT_NETWORK_AND_PHYSICAL_ISOLATED = ADJACENT_NETWORK * PHYSICAL_ISOLATED

    INTERNAL_NETWORK_AND_PHYSICAL_PUBLIC = INTERNAL_NETWORK * PHYSICAL_PUBLIC
    INTERNAL_NETWORK_AND_PHYSICAL_RESTRICTED = INTERNAL_NETWORK * PHYSICAL_RESTRICTED
    INTERNAL_NETWORK_AND_PHYSICAL_ISOLATED = INTERNAL_NETWORK * PHYSICAL_ISOLATED

    PHYSICAL_PUBLIC_AND_LOCAL = PHYSICAL_PUBLIC * LOCAL
    PHYSICAL_RESTRICTED_AND_LOCAL = PHYSICAL_RESTRICTED * LOCAL
    PHYSICAL_ISOLATED_AND_LOCAL = PHYSICAL_ISOLATED * LOCAL

    _vectors = {
        "rn": "REMOTE_NETWORK",
        "an": "ADJACENT_NETWORK",
        "in": "INTERNAL_NETWORK",
        "l": "LOCAL",
        "pp": "PHYSICAL_PUBLIC",
        "pr": "PHYSICAL_RESTRICTED",
        "pi": "PHYSICAL_ISOLATED",
        # combinations
        "rnpp": "REMOTE_NETWORK_AND_PHYSICAL_PUBLIC",
        "rnpr": "REMOTE_NETWORK_AND_PHYSICAL_RESTRICTED",
        "rnpi": "REMOTE_NETWORK_AND_PHYSICAL_ISOLATED",
        "anpp": "ADJACENT_NETWORK_AND_PHYSICAL_PUBLIC",
        "anpr": "ADJACENT_NETWORK_AND_PHYSICAL_RESTRICTED",
        "anpi": "ADJACENT_NETWORK_AND_PHYSICAL_ISOLATED",
        "inpp": "INTERNAL_NETWORK_AND_PHYSICAL_PUBLIC",
        "inpr": "INTERNAL_NETWORK_AND_PHYSICAL_RESTRICTED",
        "inpi": "INTERNAL_NETWORK_AND_PHYSICAL_ISOLATED",
        "ppl": "PHYSICAL_PUBLIC_AND_LOCAL",
        "prl": "PHYSICAL_RESTRICTED_AND_LOCAL",
        "pil": "PHYSICAL_ISOLATED_AND_LOCAL",
    }


class AttackComplexity(BaseEnum):
    """
    Vector: AC
    Mandatory: yes
    """
    LOW = D("0.77")
    HIGH = D("0.44")


class PrivilegeRequired(BaseEnum):
    """
    Vector: PR
    Mandatory: yes
    """
    NONE = D("0.85")
    LOW = D("0.62")
    HIGH = D("0.27")


class UserInteraction(BaseEnum):
    """
    Vector: UI
    Mandatory: yes
    """
    NONE = D("0.85")
    REQUIRED = D("0.62")

class Age(BaseEnum):
    """
    Vector: Y
    Mandatory: yes
    """
    YEAR1 = D("1.5")
    YEARS3 = D("1.2")
    MORE3YEARS = D("1.0")
    UNKNOWN = D("1.0")

    _vectors = {
        "1": "YEAR1",
        "3": "YEARS3",
        "O": "MORE3YEARS",
        "U": "1YEAR",
    }

class Scope(BaseEnum):
    """
    Vector: S
    Mandatory: yes
    """
    UNCHANGED = D("0")
    CHANGED = D("1")


# Impacts
class ConfidentialityImpact(BaseEnum):
    """
    Vector: C
    Mandatory: yes
    """
    HIGH = D("0.56")
    LOW = D("0.22")
    NONE = D("0")


class IntegrityImpact(BaseEnum):
    """
    Vector: I
    Mandatory: yes
    """
    HIGH = D("0.56")
    LOW = D("0.22")
    NONE = D("0")


class AvailabilityImpact(BaseEnum):
    """
    Vector: A
    Mandatory: yes
    """
    HIGH = D("0.56")
    LOW = D("0.22")
    NONE = D("0")


# Temporal metrics
class ExploitCodeMaturity(BaseEnum):
    """
    Vector: E
    """
    NOT_DEFINED = NotDefined(D("1"))
    HIGH = D("1")
    FUNCTIONAL = D("0.97")
    PROOF_OF_CONCEPT = D("0.94")
    UNPROVEN = D("0.91")


class RemediationLevel(BaseEnum):
    """
    Vector: RL
    """
    NOT_DEFINED = NotDefined(D("1"))
    UNAVAILABLE = D("1")
    WORKAROUND = D("0.97")
    TEMPORARY_FIX = D("0.96")
    OFFICIAL_FIX = D("0.95")


class ReportConfidence(BaseEnum):
    """
    Vector: RC
    """
    NOT_DEFINED = NotDefined(D("1"))
    CONFIRMED = D("1")
    REASONABLE = D("0.96")
    UNKNOWN = D("0.92")


class ConfidentialityRequirement(BaseEnum):
    """
    Vector: CR
    """
    NOT_DEFINED = NotDefined(D("1"))
    HIGH = D("1.5")
    MEDIUM = D("1")
    LOW = D("0.5")


class IntegrityRequirement(BaseEnum):
    """
    Vector: IR
    """
    NOT_DEFINED = NotDefined(D("1"))
    HIGH = D("1.5")
    MEDIUM = D("1")
    LOW = D("0.5")


class AvailabilityRequirement(BaseEnum):
    """
    Vector: AR
    """
    NOT_DEFINED = NotDefined(D("1"))
    HIGH = D("1.5")
    MEDIUM = D("1")
    LOW = D("0.5")


ModifiedAttackVector = AttackVector.extend("ModifiedAttackVector",
                                           {"NOT_DEFINED": NotDefined()},
                                           "Vector: MAV")

ModifiedAttackComplexity = AttackComplexity.extend("ModifiedAttackComplexity", {"NOT_DEFINED": NotDefined()},
                                                   "Vector: MAC")

ModifiedPrivilegesRequired = PrivilegeRequired.extend("ModifiedPrivilegesRequired", {"NOT_DEFINED": NotDefined()},
                                                      "Vector: MPR")

ModifiedUserInteraction = UserInteraction.extend("ModifiedUserInteraction", {"NOT_DEFINED": NotDefined()},
                                                 "Vector: MUI")

ModifiedAge = Age.extend("ModifiedAge", {"NOT_DEFINED": NotDefined()},
                                                 "Vector: MY")

ModifiedScope = Scope.extend("ModifiedScope", {"NOT_DEFINED": NotDefined()}, "Vector: MS")

ModifiedConfidentialityImpact = ConfidentialityImpact.extend("ModifiedConfidentialityImpact",
                                                             {"NOT_DEFINED": NotDefined()}, "Vector: MC")

ModifiedIntegrityImpact = IntegrityImpact.extend("ModifiedIntegrityImpact", {"NOT_DEFINED": NotDefined()}, "Vector: MI")

ModifiedAvailabilityImpact = AvailabilityImpact.extend("ModifiedAvailabilityImpact", {"NOT_DEFINED": NotDefined()},
                                                       "Vector: MA")

OPTIONAL_VALUES = {
    ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired,
    ModifiedUserInteraction, ModifiedAge, ModifiedScope, ModifiedConfidentialityImpact,
    ModifiedIntegrityImpact, ModifiedAvailabilityImpact
}

ORDERING = (
    AttackVector,
    AttackComplexity,
    PrivilegeRequired,
    UserInteraction,
    Age,

    Scope,
    ConfidentialityImpact,
    IntegrityImpact,
    AvailabilityImpact,

    ExploitCodeMaturity,
    RemediationLevel,
    ReportConfidence,

    ConfidentialityRequirement,
    IntegrityRequirement,
    AvailabilityRequirement,

    ModifiedAttackVector,
    ModifiedAttackComplexity,
    ModifiedPrivilegesRequired,
    ModifiedUserInteraction,
    ModifiedAge,
    ModifiedScope,

    ModifiedConfidentialityImpact,
    ModifiedIntegrityImpact,
    ModifiedAvailabilityImpact
)

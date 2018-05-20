from decimal import Decimal as D

from cvsslib.base_enum import BaseEnum, NotDefined


# Taken from https://www.first.org/cvss/specification-document#i8.4

# Exploitability metrics
class AttackVector(BaseEnum):
    """
    Vector: AV
    Mandatory: yes
    """
    NETWORK = D("0.85")
    ADJACENT_NETWORK = D("0.62")
    LOCAL = D("0.55")
    PHYSICAL = D("0.2")


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

ModifiedScope = Scope.extend("ModifiedScope", {"NOT_DEFINED": NotDefined()}, "Vector: MS")

ModifiedConfidentialityImpact = ConfidentialityImpact.extend("ModifiedConfidentialityImpact",
                                                             {"NOT_DEFINED": NotDefined()}, "Vector: MC")

ModifiedIntegrityImpact = IntegrityImpact.extend("ModifiedIntegrityImpact", {"NOT_DEFINED": NotDefined()}, "Vector: MI")

ModifiedAvailabilityImpact = AvailabilityImpact.extend("ModifiedAvailabilityImpact", {"NOT_DEFINED": NotDefined()},
                                                       "Vector: MA")

OPTIONAL_VALUES = {
    ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired,
    ModifiedUserInteraction, ModifiedScope, ModifiedConfidentialityImpact,
    ModifiedIntegrityImpact, ModifiedAvailabilityImpact
}

ORDERING = (
    AttackVector,
    AttackComplexity,
    PrivilegeRequired,
    UserInteraction,

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
    ModifiedScope,

    ModifiedConfidentialityImpact,
    ModifiedIntegrityImpact,
    ModifiedAvailabilityImpact
)

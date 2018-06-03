import operator

from cvsslib import cvss3, cvss2, rvss
from cvsslib.utils import get_enums, run_calc


class VectorError(ValueError):
    def __init__(self, message):
        self.message = message


def detect_vector(vector):
    if vector.startswith("CVSS"):
        if vector.startswith("CVSS:3.0"):
            module = cvss3
        else:
            module = cvss2
    else:
        if vector.startswith("RVSS:1.0"):
            module = rvss
        else:
            module = None


    return module


def to_vector(module, getter):
    vectors = []

    ordering = getattr(module, 'ORDERING', None)

    for name, enum in get_enums(module):
        enum_attr = getter(enum)
        vector = enum_attr.get_options()["vector"]

        key = enum_attr.get_value_key()

        if key is None:
            continue

        vectors.append((vector, key, ordering.index(enum) if ordering else None))

    if ordering:
        vectors = sorted(vectors, key=operator.itemgetter(2))
        vectors = ("{0}:{1}".format(vector, key) for vector, key, _ in vectors)
    else:
        vectors = ("{0}:{1}".format(vector, key) for vector, key, _ in vectors)
        vectors = sorted(vectors)

    res = "/".join(vectors)
    if module is cvss3:
        res = "CVSS:3.0/" + res

    return res


def calculate_vector(vector, module):
    vector_values = parse_vector(vector, module)

    def _getter(enum_type):
        if enum_type not in vector_values:
            ret = enum_type.get_default()
        else:
            ret = vector_values[enum_type]

        return ret

    return run_calc(module.calculate, getter=_getter)


def parse_vector(vector, module=None, mandatory_error=True):
    if module is None:
        module = detect_vector(vector)

    vector_map, vector_values = {}, {}
    mandatory_keys, given_keys = set(), set()
    enums = dict(get_enums(module))

    for name, enum in enums.items():
        options = enum.get_options()
        vector_name = options["vector"]

        vector_map[vector_name] = enum
        if options.get("mandatory", "") == "yes":
            mandatory_keys.add(vector_name)

    split_vector = vector.split("/")

    for part in split_vector:
        if not part:
            continue

        key, value = part.split(":")

        if key == "CVSS":
            continue  # CVSS3 is prefixed with CVSS:3.0/

        if key not in vector_map:
            raise VectorError("Unknown key {0} in {1} vector".format(key, module.__name__))

        enum = vector_map[key]
        try:
            value_from_key = enum.get_value_from_vector_key(value)
        except RuntimeError as e:
            raise VectorError(*e.args)
        vector_values[enum] = value_from_key
        given_keys.add(key)

    required_diff = mandatory_keys.difference(given_keys)

    if required_diff:
        if mandatory_error:
            raise VectorError("Missing mandatory keys {0}".format(required_diff))

        for enum_key in required_diff:
            enum = vector_map[enum_key]
            default = enum.get_default()
            vector_values[enum] = default

    return vector_values

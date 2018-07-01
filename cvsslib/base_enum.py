import enum
import inspect

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache


class NotDefined(object):
    def __init__(self, value=None):
        self.value = value
        self.name = "NOT_DEFINED"


def make_display_name(str):
    return " ".join(
        s.capitalize() for s in str.lower().split("_")
    )


class BaseEnum(enum.Enum):
    @classmethod
    @lru_cache()
    def get_options(cls):
        docstring = inspect.getdoc(cls)
        if docstring is None:
            return {}

        lines = docstring.strip().split("\n")
        options = {
            line.split(":")[0].lower().strip(): line.split(":")[1].strip()
            for line in lines
            }
        return options

    @classmethod
    def members(self):
        return (
            (name, value) for name, value in self.__members__.items() if not name.startswith("_")
        )

    @classmethod
    def get_default(cls):
        if hasattr(cls, "NOT_DEFINED"):
            default = cls.NOT_DEFINED
        elif hasattr(cls, "NONE"):
            default = cls.NONE
        else:
            default = cls(min(value.value for name, value in cls.members()))
        return default

    def get_value_key(self):
        default_vectors = {}

        cls = self.__class__
        if hasattr(cls, "_vectors"):
            default_vectors = {name: vec for vec, name in cls._vectors.value.items()}

        if self.name == "NOT_DEFINED":
            return None
        elif self.name in default_vectors.keys():
            for key, v in default_vectors.items():
                if key == self.name:
                    return v.upper()
        else:
            value = self.name[0]

        return value.upper()

    @classmethod
    @lru_cache()
    def get_value_from_vector_key(cls, key):
        key = key.lower()
        # print(key)

        if key in {"x", "nd"} and hasattr(cls, "NOT_DEFINED"):
            return cls.NOT_DEFINED

        vector_override = {}

        if hasattr(cls, "_vectors"):
            vector_override = cls._vectors.value

        if key in vector_override:
            # print(getattr(cls, vector_override[key]))
            return getattr(cls, vector_override[key])

        # print(cls.members())
        for name, value in cls.members():
            # print(name.lower())
            if name == "NOT_DEFINED" or name in vector_override.values():
                continue

            if name[0].lower() == key:
                # print(type(value))
                return value

        raise RuntimeError("Unknown vector key '{0}' for {1}".format(key, cls.__name__))

    @classmethod
    def choices(cls):
        return [(value.value if not isinstance(value.value, NotDefined) else value.value.value,
                 make_display_name(name)) for name, value in cls.members()]

    @classmethod
    def extend(cls, name, extra, doc="", mod=None):
        new_cls = enum.Enum(
            value=name,
            names=cls.to_mapping(extra),
            type=BaseEnum
        )
        new_cls._parent = cls
        new_cls.__doc__ = doc or cls.__doc__
        new_cls.__module__ = mod or cls.__module__
        return new_cls

    @classmethod
    def to_mapping(cls, extra=None):
        returner = {
            name: value.value
            for name, value in cls.members()
        }

        if extra:
            returner.update(extra)

        return returner

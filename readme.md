# Robot Vulnerability Scoring System (RVSS) Python 3 reference implementation.

*Work inspired by https://github.com/ctxis/cvsslib. Paper available at https://arxiv.org/pdf/1807.10357.pdf*.

----

- **Current version**: 1.0
- **License**: GPLv3

----

This repository provides a Python 3 (*only Python 3*) library for calculating robot vulnerability scores. The library extends `cvsslib` to support the following scoring systems:
- CVSSv2
- CVSSv3
- RVSSv1

From the original README:

> Examples on how to use the library is shown below, and there is some documentation on the internals within the `docs` directory. The library is designed to be completely extendable, so it is possible to implement your own custom scoring systems (or those of your clients) and have it work with the same API, and with the same bells and whistles.

## How to cite our work
```
@ARTICLE{2018arXiv180710357M,
   author = {{Mayoral Vilches}, V. and {Gil-Uriarte}, E. and {Zamalloa Ugarte}, I. and 
	{Olalde Mendia}, G. and {Izquierdo Pis{\'o}n}, R. and {Alzola Kirschgens}, L. and 
	{Bilbao Calvo}, A. and {Hern{\'a}ndez Cordero}, A. and {Apa}, L. and 
	{Cerrudo}, C.},
    title = "{Towards an open standard for assessing the severity of robot security vulnerabilities, the Robot Vulnerability Scoring System (RVSS)}",
  journal = {ArXiv e-prints},
archivePrefix = "arXiv",
   eprint = {1807.10357},
 primaryClass = "cs.RO",
 keywords = {Computer Science - Robotics, Computer Science - Cryptography and Security},
     year = 2018,
    month = jul,
   adsurl = {http://adsabs.harvard.edu/abs/2018arXiv180710357M},
  adsnote = {Provided by the SAO/NASA Astrophysics Data System}
}
```

## Install
```bash
python3 setup.py install
```

## Try it out
#### RVSSv1
```bash
$ rvss RVSS:1.0/AV:AN/AC:L/PR:N/UI:N/Y:O/S:U/C:N/I:L/A:N/H:H
Base Score:	7.3
Temporal:	7.3
Environment:	7.3
```

#### CVSSv3
```bash
$ rvss CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Base Score:	8.8
Temporal:	8.8
Environment:	8.8
```

#### CVSSv2
```bash
$ rvss CVSS:2.0/AV:L/AC:M/Au:N/C:N/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:L/AR:H
Base Score:	5.4
Temporal:	4.4
Environment:	6.9
```


## API

It's pretty simple to use. `cvsslib` has a `cvss2`, `cvss3` and `rvss` sub modules that contains all of the enums and calculation code. There are also some functions to manipulate vectors that take these cvss modules
as arguments. E.G:

```python
from cvsslib import cvss2, cvss3, calculate_vector

vector_v2 = "AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H"
calculate_vector(vector_v2, cvss2)
>> (5, 3.5, 1.2)

vector_v3 = "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N"
calculate_vector(vector_v3, cvss3)
>> (5.8, 5.8, 7.1)
```

You can access every CVSS enum through the `cvss2` or `cvss3` modules:

```python
from cvsslib import cvss2
# In this case doing from 'cvsslib.cvss2.enums import *' might be less verbose.
value = cvss2.ReportConfidence.CONFIRMED

if value != cvss2.ReportConfidence.NOT_DEFINED:
    do_something()
```  

There are some powerful mixin functions if you need a class with CVSS members. These functions
take a cvss version and return a base class you can inherit from. This class hassome utility functions like
`to_vector()` and `from_vector()` you can use.

```python
from cvsslib import cvss3, class_mixin

BaseClass = class_mixin(cvss3)  # Can pass cvss2 module instead

class SomeObject(BaseClass):
    def print_stats(self):
        for item, value in self.enums:
            print("{0} is {1}".format(item, value)

state = SomeObject()
print("\n".join(state.debug()))
print(state.calculate())
state.from_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N")
print("Vector: " + state.to_vector())

# Access members:
if state.report_confidence == ReportConfidence.NOT_DEFINED:
    do_something()
```

It also supports Django models. Requires the `django-enumfields` package.

```python
from cvsslib.contrib.django_model import django_mixin
from cvsslib import cvss2
from django.db import models

CVSSBase = django_mixin(cvss2)

class CVSSModel(models.Model, metaclass=CVSSBase)
    pass

# CVSSModel now has lots of enum you can use
x = CVSSModel()
x.save()
x.exploitability
```

If you want it to work with django Migrations you need to give an attribute name to the `django_mixin` function. This
should match the attribute name it is being assigned to:

```python
CVSSBase = django_mixin(cvss2, attr_name="CVSSBase")
```

And there is a command line tool available:

```python
> cvss CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N/E:P/RL:U/RC:U/CR:H/IR:L/AR:H/MAV:L/MUI:R/MS:C/MC:N/MI:L/MA:N
Base Score:     5.3
Temporal:       4.6
Environment:    1.3
```

## Custom Scoring Systems

Creating a new scoring system is very simple. First create a Python file with the correct name, e.g `super_scores.py`.
Next create some enums with the correct values for your system:

```python
 from cvsslib.base_enum import BaseEnum


 class Risk(BaseEnum):
     """
     Vector: S
     """
     HIGH = 1
     MEDIUM = 2
     LOW = 3

 class Difficulty(BaseEnum):
     """
     Vector: D
     """
     DIFFICULT = 1
     MODERATE = 2
     EASY = 3
```

And lastly add a `calculate` function in the module that accepts some vector values and
returns a result of some kind:

```python

def calculate(difficulty: Difficulty, risk: Risk):
   if difficulty == Difficulty.EASY and risk == Risk.CRITICAL:
       return "oh nuts you're screwed"

   return "You're probs ok m8"
```

Once you define this you can pass your `super_scores` module to any
cvsslib function like `calculate_vector` or `django_mixin` and it will
all just work. You can even serialize the data to and from a vector
if you define the correct `vector: X` in the enum docstrings.

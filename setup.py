#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""\
A client to submit payment orders to the Sermepa service.
"""

from setuptools import setup, find_packages

with open("README.md") as readme:
    longdesc = readme.read()

PACKAGES_DATA = {}

setup(
    name='sermepa',
    version='0.1.2',
    description = __doc__,
    author='GISCE Enginyeria',
    author_email='devel@gisce.net',
    url='http://www.gisce.net',
    license='General Public Licence 2 or later',
    long_description=longdesc,
    provides=['sermepa'],
    test_suite='sermepa',
    install_requires=[
        'pyDes',
        'simplejson',
        ],
    test_require=[
        'requests',
        ],
    packages=find_packages(),
    package_data=PACKAGES_DATA,
    scripts=[],
)

#!/usr/bin/env python3
from setuptools import setup

with open("requirements.txt", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="PyWSUS",
    author="Julien Pineault (GoSecure)",
    license="MIT",
    install_requires=requirements,
    package_data={"pywsus": ["resources/*.xml"]},
    entry_points={"console_scripts": ["pywsus=pywsus.pywsus:main"]},
)

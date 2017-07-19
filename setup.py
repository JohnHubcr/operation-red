#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='Operation Red',
    version='1.0',
    packages=find_packages(),
    description="",
    long_description=open('README.md').read(),
    author='EdOverflow',
    url='https://github.com/EdOverflow/operation-red',
    install_requires=['colorama', 'requests'],
)
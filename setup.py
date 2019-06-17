#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = "lyon"

"""
Flask-Docs
--------------
`````
"""
import sys
import ssl

ssl._create_default_https_context = ssl._create_unverified_context
from setuptools import setup

version = '0.2.1'

# Hack to prevent stupid TypeError: 'NoneType' object is not callable error on
# exit of python setup.py test # in multiprocessing/util.py _exit_function when
# running python setup.py test (see
# https://github.com/pypa/virtualenv/pull/259)

install_requires = ['Flask']

setup(
    name='Flask-API-Docs',
    version=version,
    url='https://github.com/lyonyang/flask-docs/flask_docs',
    license='BSD',
    author='Lyon Yang',
    author_email='lyon.yang@qq.com',
    maintainer='Lyon Yang',
    maintainer_email='lyon.yang@qq.com',
    description='Web API docs for Flask',
    long_description=__doc__,
    long_description_content_type="text/markdown",
    packages=[
        'flask_api_docs'
    ],
    zip_safe=False,
    install_requires=install_requires,
    tests_require=[
    ],
    platforms='any',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        # 'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6'
    ]
)

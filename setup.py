#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = "lyon"

"""
Flask-Docs
--------------
`````
"""
import sys
from setuptools import setup

version='0.1.0'

# Hack to prevent stupid TypeError: 'NoneType' object is not callable error on
# exit of python setup.py test # in multiprocessing/util.py _exit_function when
# running python setup.py test (see
# https://github.com/pypa/virtualenv/pull/259)
try:
    import multiprocessing
except ImportError:
    pass

install_requires = ['Flask']

setup(
    name='Flask-Docs',
    version=version,
    url='https://github.com/lyonyang/flask-docs/flask_docs/',
    license='BSD',
    author='Lyon Yang',
    author_email='lyon.yang@qq.com',
    maintainer='Lyon Yang',
    maintainer_email='lyon.yang@qq.com',
    description='Web API docs for Flask',
    long_description=__doc__,
    packages=[
        'flask_docs'
    ],
    zip_safe=False,
    install_requires=install_requires,
    tests_require=[
    ],
    platforms='any',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
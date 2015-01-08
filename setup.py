#!/usr/bin/env python

from setuptools import setup

setup(name='STPL',
      version='0.1',
      description='Secure Timestamped Property List',
      author='Michael Bironneau',
      author_email='michael.bironneau@openenergi.com',
      license='licence.txt',
      url='https://bitbucket.org/michael_bironneau/secure-timestamped-property-list',
      packages=['sectpl'],
      install_requires=[
      	'PyCrypto',
      	'pbkdf2'
      ],
      test_suite='test'
     )
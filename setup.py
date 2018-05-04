import os
from setuptools import setup, find_packages

setup(name='Products.PASIPAuth',
      version='0.2',
      package_data = {'Products.PASIPAuth': ['www/*', 'configure.zcml']},
      description='PAS plugin that authenticates by ip address',
      long_description=open("README.txt").read(),
      classifiers=[
        "Framework :: Plone",
        "Framework :: Zope2",
        "Programming Language :: Python",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Topic :: Software Development :: Libraries :: Python Modules",
      ],
      author='Izak Burger',
      author_email='izak@upfrontsystems.co.za',
      url='http://www.upfrontsystems.co.za/',
      license='GPL',
      packages=find_packages(),
      namespace_packages=['Products'],
)

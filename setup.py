import os
from setuptools import setup, find_packages

setup(name='Products.PASIPAuth',
      version='0.3',
      description='PAS plugin that authenticates by ip address',
      long_description=open("README.txt").read(),
      classifiers=[
        "Framework :: Plone",
        "Framework :: Zope4",
        "Programming Language :: Python 3",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Topic :: Software Development :: Libraries :: Python Modules",
      ],
      author='Izak Burger',
      author_email='izak@upfrontsystems.co.za',
      url='http://www.upfrontsystems.co.za/',
      license='GPL',
      packages=find_packages(exclude=["ez_setup"]),
      namespace_packages=['Products'],
      include_package_data=True,
      # package_data = {'Products.PASIPAuth': ['www/*', 'configure.zcml']},
      install_requires=[
          "setuptools",
          # -*- Extra requirements: -*-
      ],
      entry_points="""
        # -*- Entry points: -*-
        """,
 
)

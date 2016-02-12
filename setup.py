
import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [
        dirpath
        for dirpath, dirnames, filenames in os.walk(package)
        if os.path.exists(os.path.join(dirpath, '__init__.py'))
    ]


setup(
    name='MailBeaker SDK',
    version='0.2.2',
    packages=get_packages('sdk'),
    long_description=open('README.md').read(),
    install_requires=[
        'statsd==3.0.1',
        'python-jose==0.2.0',
        'redis==2.10.3',
        'requests>=2.4.1, <3.0.0'
    ]
)

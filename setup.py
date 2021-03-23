import os
from setuptools import setup, find_packages


def get_requirements():
    basedir = os.path.dirname(__file__)
    try:
        with open(os.path.join(basedir, 'requirements.txt')) as f:
            return f.readlines()
    except FileNotFoundError:
        raise RuntimeError('No requirements info found.')


setup(
    name='ssh-crypt',
    version='1.0',
    license='BSD',
    author='Maxim Nikitenko',
    author_email='iam@sets88.com',
    packages=find_packages(),
    description='ssh-crypt is a tool to encrypt/decrypt data using your ssh key from ssh-agent',
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=get_requirements(),
    python_requires='>=3.5',
    entry_points={
        'console_scripts': [
            'ssh-crypt = ssh_crypt:main',
        ]
    }
)

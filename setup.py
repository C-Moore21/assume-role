from setuptools import setup

setup(
    name='assume-role',
    version='0.1.0',
    description='assumerole: a CLI tool making it easy to assume IAM roles through an AWS Bastion account.',
    author='Aidan Melen',
    author_email='amelen@exactsciences.com',
    url='https://support.sampleminded.com',
    classifiers=[
        'Development Status :: Production',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.6.3'
    ],
    keywords='sampleminded python utilities',
    packages=['assume_role'],
    include_package_data = True,
    install_requires=['awscli==1.14.53', 'boto3==1.6.6'],
    entry_points={
        'console_scripts': [
            'assume-role = assume_role.__main__:main',
            'init-assume-role = init_assume_role.__main__:main',
        ]
    }
)

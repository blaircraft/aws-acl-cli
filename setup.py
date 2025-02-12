from setuptools import setup

setup(
    name='acl',
    version='1.0.0',
    py_modules=['acl'],
    install_requires=[
        'Click',
        'boto3',
        'textual'
    ],
    entry_points={
        'console_scripts': [
            'acl = acl:acl',
        ],
    },
)

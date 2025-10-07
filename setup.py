from setuptools import setup, find_packages

setup(
    name="will-encrypt",
    version="1.0.0",
    packages=find_packages(where="."),
    package_dir={"": "."},
    entry_points={
        "console_scripts": [
            "will-encrypt=src.main:main",
        ],
    },
)

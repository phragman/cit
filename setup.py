from setuptools import setup

setup(
    name="Crypto Interface Tool",
    version="0.1.0",
    py_modules=["cit"],
    install_requires=[
        "click>=7.0",
        "cryptography>=3.0"
    ],
    entry_points={
        "console_scripts": [
            "cit=cit:cli"
        ],
    },
    author="Phragman",
    author_email="a@rel2.com",
    description="A CLI tool for generating keys and encrypting/decrypting using RSA, EC, and DSA",
    long_description=open("README.md", encoding="utf-8").read() if True else "",
    long_description_content_type="text/markdown",
    url="https://github.com/phragman/cit",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)

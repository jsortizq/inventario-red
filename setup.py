"""Minimal setuptools configuration for inventario-red."""
from setuptools import setup, find_packages

setup(
    name="inventario-red",
    version="2.0.0",
    author="Juan Sebastian Ortiz Quintero",
    author_email="jsortizq@gmail.com",
    description="Escáner de redes locales e industriales (OT) sin Nmap",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/jsortizq/inventario-red",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "openpyxl>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "inventario-red=src.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
)

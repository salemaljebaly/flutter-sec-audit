"""
Setup script for FlutterSecAudit
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="fluttersec",
    version="0.1.0",
    author="FlutterSecAudit Contributors",
    author_email="",
    description="Automated security scanner for Flutter apps with attack simulation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/salemaljebaly/flutter-sec-audit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.10",
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.0",
        "pyyaml>=6.0.1",
        "jinja2>=3.1.3",
        "plotly>=5.18.0",
    ],
    entry_points={
        "console_scripts": [
            "fluttersec=fluttersec.cli:main",
        ],
    },
    include_package_data=True,
)

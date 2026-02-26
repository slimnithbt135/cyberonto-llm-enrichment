#!/usr/bin/env python3
"""
CyberRule: Deterministic Rule-Based Ontology Enrichment for Cybersecurity
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README if exists
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

setup(
    name="cyberrule",
    version="1.0.0",
    author="Thabet Slimani",
    author_email="thabet.slimani@gmail.com",
    description="Deterministic rule-based ontology enrichment for CVE processing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/slimnithbt135/cyberonto-llm-enrichment",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=[
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "tqdm>=4.64.0",
        "rdflib>=6.2.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
        ],
        "eval": [
            "scikit-learn>=1.2.0",
            "scipy>=1.9.0",
            "pandas>=1.5.0",
            "numpy>=1.23.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cyberrule=cyberrule.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "cyberrule": ["patterns/*.yml"],
    },
)

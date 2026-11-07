from pathlib import Path
from runpy import run_path

import setuptools

VERSION = run_path(str(Path(__file__).parent / "dshield_parser" / "_version.py"))["__version__"]

setuptools.setup(
    name="dshield_parser",
    version=VERSION,
    author="Jesse La Grew",
    author_email="jlagrew.github@proton.me",
    description="This program has utilities to download, parse and enrich DShield honeypot data",
    url="https://github.com/jslagrew/dshield-parser",
    packages=setuptools.find_packages(),
    #entry_points = {
    #    'console_scripts':
    #    ['summarize_urls=utils.json:summarize_urls',
    #     'summarize_urls=utils.json:summarize_commands']
    #},
    python_requires='>=3.12',
    install_requires=[
        "dnspython>=2.6.1",
        "matplotlib>=3.6.3",
        "numpy>=1.26.0",
        "pandas>=2.0.3",
        "requests>=2.32.3",
        "scikit-learn>=1.2.2",
        "shodan>=1.28.0",
        "SQLAlchemy>=2.0.31",
    ],
    extras_require={
        "geoip": ["geoip2>=4.8.0"],
    },
)


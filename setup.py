import setuptools

setuptools.setup(
    name="dshield_parser",
    version="0.1.7",
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
        "matplotlib>=3.6.3",
        "numpy>=1.26.0",
        "pandas>=2.0.3",
        "requests>=2.32.3",
        "scikit-learn>=1.2.2",
        "shodan>=1.28.0",
        "SQLAlchemy>=2.0.31",
    ],
)

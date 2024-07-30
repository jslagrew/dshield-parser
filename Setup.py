import setuptools

setuptools.setup(
    name="dshield_parser",
    version="0.1.1",
    author="Jesse La Grew",
    author_email="jlagrew.github@proton.me",
    description="This program has utilities to download, parse and enrich DSHield honeypot data",
    url="https://github.com/jslagrew/dshield-parser",
    packages=setuptools.find_packages(),
    #entry_points = {
    #    'console_scripts':
    #    ['summarize_urls=utils.json:summarize_urls',
    #     'summarize_urls=utils.json:summarize_commands']
    #},
    python_requires='>3.6'
    #install_requires=['matplotlib', 'numpy', 'pandas', 'Requests', 'scikit_learn', 'shodan', 'SQLAlchemy']
)
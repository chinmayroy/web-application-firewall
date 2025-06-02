from setuptools import setup, find_packages

setup(
    name="web-application-firewall",
    version="0.1.0",
    description="Django middleware Web Application Firewall",
    author="Chinmay Roy",
    author_email="chinmayroycom@gmail.com",
    url="https://github.com/chinmayroy/web-application-firewall",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "Django>=3.2",
    ],
    classifiers=[
        "Framework :: Django",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    keywords="django waf firewall security middleware",
)

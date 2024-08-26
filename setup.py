from setuptools import setup, find_packages

setup(
    name="fastapi-gae-logging",
    version="0.0.1",
    description="Custom Cloud Logging handler for FastAPI applications deployed in Google App Engine. \
    Groups logs coming from the same request lifecycle and propagates the maximum log level \
    throughout the request lifecycle using middleware and context management.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/chrisK824/fastapi-gae-logging",
    author="Chris Karvouniaris",
    author_email="christos.karvouniaris247@gmail.com",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.112.2",
        "google-cloud-logging>=3.10.0",
    ],
    python_requires=">=3.7",
    license="MIT",
    license_files=["LICENSE"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
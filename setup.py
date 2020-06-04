import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()  # noqa


def get_requirements():
    with open("requirements.txt") as req_file:
        requirements = [
            l.strip() for l in req_file.readlines() if len(l.strip())
        ]
    return requirements


setuptools.setup(
    name="kyros",
    version="0.0.2",
    author="loncat",
    author_email="me@lcat.dev",
    description="A Python wrapper for WhatsApp Web API",
    long_description=long_description,
    long_description_content_type="text/plain",
    url="https://github.com/p4kl0nc4t/kyros",
    packages=setuptools.find_packages(),
    install_requires=get_requirements(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: MIT License",
        "Operating System :: OS Independent",
    ],
)

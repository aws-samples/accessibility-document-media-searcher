import setuptools


with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="adms",
    version="1.0.0",

    description="Acessibility Document Media Searcher created with AWS CDK for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="@amandaqt, @gcouto, @letdorne",

    package_dir={"": "stack"},
    packages=setuptools.find_packages(where="stack"),

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "License :: OSI Approved :: Apache Software License",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)

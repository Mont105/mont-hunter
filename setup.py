from setuptools import setup, find_packages

setup(
    name="monthunter",
    version="1.0.0",
    description="Static triage for binaries and installers with IOC extraction and optional YARA scanning.",
    author="Mont105",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["pefile>=2023.2.7"],
    extras_require={
        "decompile": ["decompyle3>=3.9.0", "uncompyle6>=3.9.0"],
        "rich": ["rich"],
    },
    entry_points={
        "console_scripts": [
            "mont-hunter=monthunter.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)

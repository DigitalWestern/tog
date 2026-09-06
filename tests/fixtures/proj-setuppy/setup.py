from pathlib import Path

from setuptools import setup

requirements = [
    line.strip()
    for line in (Path(__file__).parent / "requirements" / "requirements.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="proj-setuppy",
    version="0.1.0",
    packages=["setuppkg"],
    install_requires=requirements,
    python_requires=">=3.10,<3.15",
)

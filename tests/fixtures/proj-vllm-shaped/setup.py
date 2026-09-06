from pathlib import Path

from setuptools import setup

root = Path(__file__).parent / "requirements"
requirements = [
    line.strip()
    for name in ("common.txt", "cpu.txt")
    for line in (root / name).read_text().splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="proj-vllm-shaped",
    version="0.1.0",
    install_requires=requirements,
    python_requires=">=3.10,<3.15",
)

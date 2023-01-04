from setuptools import setup
from setuptools_rust import Binding, RustExtension

from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="tpke",
    description="Ferveo DKG scheme",
    long_description=long_description,
    long_description_content_type="text/markdown",
    version="0.1.0",
    author="Piotr Roslaniec",
    author_email="p.roslaniec@gmail.com",
    url="https://github.com/nucypher/ferveo/tree/master/tpke-python",
    rust_extensions=[RustExtension(
        "tpke._tpke", binding=Binding.PyO3, debug=False)],
    packages=["tpke"],
    package_data={
        'tpke': ['py.typed', '__init__.pyi'],
    },
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Programming Language :: Rust",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security :: Cryptography",
    ],
)

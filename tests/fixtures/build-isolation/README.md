Build-isolation e2e specimens:

- tomli-w 1.2.0: a small Flit-backed pure-Python sdist.
- insightface 0.7.3: setuptools with NumPy and Cython build requirements.
- tokenizers 0.13.3: setuptools-rust with a lockless Cargo workspace.

The test records the tokenizers CPython 3.12 limitation and uses fastuuid
0.14.0 as the smaller Rust fallback on this branch, which has no CPython
3.11 pin yet.

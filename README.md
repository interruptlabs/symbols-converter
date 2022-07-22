# Introduction

`symbols-converter` converts symbols from a `.idb` file to a `.sym`, `.json` or `.txt` file. Use the `-h` option for detailed help.

# Installation

## Permanent

Clone the repository and run the following from its root directory:

```bash
pip install .
```

You should now be able to run `symbols-converter`.

## Temporary

Clone the repository and run the following from its root directory:

```bash
python -m sc
```

# Scripts

There are a couple of useful scripts:

- `util.py` - Used for development activities such as testing and formatting.
- `download_sym_files.py` - Downloads all the `vxworks.sym` files from GitHub.

# Development

To set up a development environment, clone the repository and run the following from its root directory:

```python
pipenv install --dev
pipenv shell
pre-commit install
```


# Falco rules analyzer script

This script has utilities to help analyze and extract information from Falco rules files.

## Requirements

You need [Python 3.7+](https://www.python.org/), and [Poetry](https://python-poetry.org/docs/#installation) to install dependencies and create a virtual environment.

```console
$ python --version
Python 3.7.8

$ poetry -V
Poetry version 1.1.4
```

## Set up

Clone this repository, and use `Poetry` inside it to install dependencies in an automatically created virtual environment.

```console
$ git clone https://github.com/sysdiglabs/falco_analyzer.git
$ cd falco_analyzer
$ poetry install
```

Then you can execute this script with:
```console
$ poetry run python3 falco_analyzer.py help
```

### Virtual environment and Poetry

The default poetry behaviour is to create a virtual environment in `{cache-dir}/virtualenvs`. You can run commands using that environment with `poetry run ...` or activate it with `poetry shell`. For more information, check [Poetry official documentation](https://python-poetry.org/docs/basic-usage/).


## Usage

```
poetry run python3 falco_analyzer.py [command] [parameters]

Example:
poetry run python3 falco_analyzer.py merge_tags rule_file.yaml tag_file.yaml output_file.yaml

Commands

  help
     Show this help

  merge_tags [input_falco_rules_file] [tags_file] [output_file]
     Merges tags to rules from input file, and outputs new rules to a new file.

  get_csv_tags [input_falco_rules_file] [output_csv_file]
     Writes a CSV file with a Falco rule per row, with different tags used on each one
```

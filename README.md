# Falco rules analyzer script

This script has utilities to help analyze and extract information from Falco rules files.

## Requirements

You need [Python 3.7+](https://www.python.org/). It is recommended to use [pipenv](https://github.com/pypa/pipenv) to install Python dependences and a [virtual environment](https://github.com/pypa/pipenv#-usage)

```console
$ python --version
Python 3.7.8

$ pipenv --version
pipenv, version 2020.6.2
```

## Set up

Clone this repository, and use `pipenv` inside it to create a virtual environment.

```console
$ git clone https://github.com/sysdiglabs/falco_analyzer.git
$ cd falco_analyzer
$ pipenv shell
```

To install all dependences, then use:
```console
$ pipenv install
```

Then you can start executing the script like this:
```console
$ python3 falco_analyzer.py help
```


## Usage

```
python3 falco_analyzer.py [command] [parameters]

Example:
python3 falco_analyzer.py merge_tags rule_file.yaml tag_file.yaml output_file.yaml

Commands

  help
     Show this help

  merge_tags [input_falco_rules_file] [tags_file] [output_file]
     Merges tags to rules from input file, and outputs new rules to a new file.

  get_csv_tags [input_falco_rules_file] [output_csv_file]
     Writes a CSV file with a Falco rule per row, with different tags used on each one
```

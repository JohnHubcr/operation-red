# Operation Red ![](https://api.travis-ci.org/EdOverflow/operation-red.svg?branch=master)

A simple python scanner designed to find open redirect vulnerabilities.

**WARNING:** This is a work in progress!

# Table of Contents

- Installing
- Dependencies
- Usage
- Contributing
- License

# Installing

```
$ git clone https://github.com/EdOverflow/operation-red.git
$ cd operation-red
$ python setup.py install
```

# Dependencies

- Requests
- Colorama

# Usage

**Operation Red** supports Python 2 & 3 and can b used to scan a single URL or a list of domains in a text file.

```
$ python openred.py -h
usage: openred.py [-h] [-u URL] [-t TXT]

Open redirect vulnerability scanner.

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  Scan individual URL for open redirect vulnerabilities
  -t TXT, --txt TXT  Scan text file for open redirect vulnerabilities
```

```
$ python openred.py -u http://example.com/
```

# Contributing


Contributions from the public are welcome.

### Using the issue tracker 💡

The issue tracker is the preferred channel for bug reports and features requests. [![GitHub issues](https://img.shields.io/github/issues/EdOverflow/operation-red.svg?style=flat-square)](https://github.com/EdOverflow/operation-red/issues)

### Issues and labels 🏷

The bug tracker utilizes several labels to help organize and identify issues.

### Guidelines for bug reports 🐛

Use the GitHub issue search — check if the issue has already been reported.

# License

MIT. Copyright (c) [EdOverflow](https://github.com/EdOverflow).

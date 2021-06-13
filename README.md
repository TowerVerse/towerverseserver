# OpenDogeServer [![CircleCI](https://circleci.com/gh/OpenDoge/opendogeserver.svg?style=shield)](https://circleci.com/gh/OpenDoge/opendogeserver)

## What's this?

**This repository includes the source code of the current server of OpenDoge.**

**The servers are available at: [master version](https://opendoge.herokuapp.com) or [beta version](https://opendoge-beta.herokuapp.com).**

**The purpose of this is for experimentation and development of similar rest APIs.**

## [Contributing](https://github.com/OpenDoge/opendogeserver/CONTRIBUTING.md)

## Installing

### Requirements:

- **OS: macOS/Linux distribution**
- **python >= 3.8.5**
- **pip**

### Procedure

- **Fork this repository**

- **```git clone {fork repository}```**

- **```cd {fork directory}```**

- **```pip install .``` or ```pip install .[tests]``` if you are planning to test newly added events.**

## Hosting locally

- **```cd {fork directory root}```**

- **(Optional) Use ```git switch beta``` to use the latest server features which may or may not be stable.**

- **```python3 opendogeserver/server.py```**

**The server will run on a designated port (5000 by default) at localhost.**

## Hosting online

**One must set the *PORT* environmental variable to inform the server that it should be attached to a specific port.**

**Otherwise the server will be attached to port 5000, at the IP of the local machine.**

# OpenDogeServer [![CircleCI](https://circleci.com/gh/OpenDoge/opendogeserver.svg?style=shield)](https://circleci.com/gh/OpenDoge/opendogeserver)

## What's this?

**This repository includes the source code of the current server of OpenDoge.**

**The servers are available at: [master version](https://opendoge.herokuapp.com) or [beta version](https://opendoge-beta.herokuapp.com).**

**The purpose of this is for experimentation and development of similar rest APIs.**

## [Contributing](https://github.com/OpenDoge/opendogeserver/blob/master/CONTRIBUTING.md)

## Installing

### Requirements:

- **OS: macOS/Linux distribution**
- **python >= 3.7.0**
- **pip**

### Procedure

- **Fork this repository**

- **```git clone {fork repository}```**

- **```cd {fork directory}```**

- **```pip install .``` and ```pip install .[tests]``` if you are planning to add new events.**

## Hosting locally

- **```cd {fork directory root}```**

- **(Optional) Use ```git switch beta``` to use the latest server features which may or may not be stable.**

- **```python3 opendogeserver/server.py --local```**

- **(In another terminal) ```python3 -m websockets ws://localhost:5000``` and try JSON requests such as: ```{"event": "totalTravellers"}```**

**The server will run on a designated port (5000 by default) at localhost.**

**Note: Passing --local means no database will be used. Otherwise set the environmental variables OPENDOGE_MONGODB_USERNAME and OPENDOGE_MONGODB_PASSWORD to the ones the OpenDoge owner has given you.**

## Hosting online

**One must set the *PORT* environmental variable as well as to inform the server that it should be attached to a specific port.**

**Otherwise the server will be attached to port 5000 by default.**

**Remember to set the environmental variables provided in order to run the production server.**

# TowerVerseServer [![CircleCI](https://circleci.com/gh/TowerVerse/towerverseserver.svg?style=shield)](https://circleci.com/gh/TowerVerse/towerverseserver)

## What's this?

**This repository includes the source code of the current server of TowerVerse.**

**The servers are available at: [master version](https://towerverse.herokuapp.com) or [beta version](https://towerverse-beta.herokuapp.com).**

**The purpose of this is for experimentation purposes and development of similar rest APIs in python.**

## [Contributing](https://github.com/TowerVerse/towerverseserver/blob/master/CONTRIBUTING.md)

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

- **```python3 towerverseserver/server.py --local```**

- **(In another terminal) ```python3 -m websockets ws://localhost:5000``` and try JSON requests such as: ```{"event": "totalTravellers"}```**

**The server will run on a designated port (5000 by default) at localhost.**

**Note: Passing --local means no database will be used. Otherwise set the environmental variables TOWERVERSE_MONGODB_USERNAME, TOWERVERSE_MONGODB_PASSWORD, TOWERVERSE_EMAIL_ADDRESS and TOWERVERSE_EMAIL_PASSWORD to the ones the TowerVerse owner has given you or to the ones corresponding to your own credentials.**

## Hosting online

**One must set the above environmental variables alongside *PORT* to inform the server that it should be attached to a specific one.**

**NOTE: *PORT* defaults to 5000.**

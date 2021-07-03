# <p align="center">**TowerVerseServer**</p>
![GitHub](https://img.shields.io/github/license/TowerVerse/towerverseserver) ![GitHub Repo stars](https://img.shields.io/github/stars/TowerVerse/towerverseserver?style=social) ![GitHub forks](https://img.shields.io/github/forks/TowerVerse/towerverseserver?style=social) ![GitHub commit activity](https://img.shields.io/github/commit-activity/m/TowerVerse/towerverseserver) ![Lines of code](https://img.shields.io/tokei/lines/github/TowerVerse/towerverseserver?branch=master)
![GitHub issues](https://img.shields.io/github/issues/TowerVerse/towerverseserver) ![GitHub Sponsors](https://img.shields.io/github/sponsors/TowerVerse)

## Branch statuses

### Master: ![CircleCI](https://circleci.com/gh/TowerVerse/towerverseserver.svg?branch=master&style=shield)

### Beta: ![CircleCI](https://circleci.com/gh/TowerVerse/towerverseserver.svg?branch=beta&style=shield)

## What's this?

**This repository includes the source code of the current server of TowerVerse.**

**The servers are available at: [master version](https://towerverse.herokuapp.com) or [beta version](https://towerverse-beta.herokuapp.com).**

**The purpose of this is for experimentation purposes and development of similar rest APIs in python.**

## [Contributing](https://github.com/TowerVerse/towerverseserver/blob/master/CONTRIBUTING.md)

## Installing

### Requirements:

- **OS: Windows 10/macOS/Linux distribution (commands shown here are for bash)**
- **python >= 3.7.0**
- **pip3**

### Procedure

- **Fork this repository**

- **```git clone {fork repository}```**

- **```cd {fork directory}```**

- **```pip install .``` and ```pip install .[tests]``` if you are planning to add new events.**

## Hosting locally

- **```cd {fork directory root}```**

- **(Optional) Type ```git switch beta``` to use the latest server features which may or may not be stable.**

- **```python3 towerverseserver/server.py --local```**

- **(In another terminal) ```python3 -m websockets ws://localhost:5000``` and try JSON requests such as: ```{"event": "createTraveller"}```**

**The server will run on a designated port (5000 by default) at localhost.**

**Note: Passing --local means no database will be used. Otherwise set the environmental variables described in the extra information at the top of the [server file](https://github.com/TowerVerse/towerverseserver/blob/master/towerverseserver/server.py).**

## Hosting online

**The *PORT* environmental variable can be set to inform that the server be attached to a specific one.**

**Remember to run the server file without any argument such as --local or --test so as to make use of the database and prevent any errors.**

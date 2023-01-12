# Gato (Github Attack TOol)

<p align="center">
  <img src="https://user-images.githubusercontent.com/2006441/212176664-2ffb61ec-1b40-49cb-8cb2-7a9127a51f3b.PNG" alt="gato"/>
</p>


Gato, or GitHub Attack Tool, is an enumeration and attack tool that allows both 
blue teamers and offensive security practitioners to evaluate the blast radius 
of a compromised personal access token within a GitHub organization.

The tool also allows searching for and thoroughly enumerating public
repositories that utilize self-hosted runners. GitHub recommends that
self-hosted runners only be utilized for private repositories, however, there
are thousands of organizations that utilize self-hosted runners.

### Who is it for?

- Security engineers who want to understand the level of access a compromised
  classic PAT could provide an attacker
- Blue teams that want to build detections for self-hosted runner attacks
- Red Teamers
- Bug bounty hunters who want to try and prove RCE on organizations that are
  utilizing self-hosted runners

### Features

* GitHub Classic PAT Privilege Enumeration
* GitHub Code Search API-based enumeration
* GitHub Action Run Log Parsing to identify Self-Hosted Runners
* Bulk Repo Sparse Clone Features
* GitHub Action Workflow Parsing
* Automated Command Execution Fork PR Creation
* Automated Command Execution Workflow Creation
* SOCKS5 Proxy Support
* HTTPS Proxy Support

### Getting Started

Gato supports OS X and Linux with at least Python 3.8.

In order to install, simply clone the repository and use pip install.

```
git clone https://github.com/praetorian-inc/gato
cd gato
pip install .
```

We also maintain a package on Pypi, which can be installed using:

```
pip install praetorian-gato
```

Gato also requires that `git` version 2.27 or above is installed and on the 
system's PATH. In order to run the fork PR attack module, `sed` must also be 
installed and present on the system's path.

For troubleshooting and additional details, such as installing in developer 
mode or running unit tests, please see the [wiki](https://github.com/praetorian-inc/gato/wiki)

### Documentation

Please see the wiki for detailed documentation, as well as opsec considerations 
for the tool's various modules!

### Contributing

Contributions are welcome! Please [review](https://github.com/praetorian-inc/gato/wiki/Project-Design) our design methodology and coding 
standards before working on a new feature!
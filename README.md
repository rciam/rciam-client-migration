# rciam-client-migration

A Python-based tool for migrating clients from MITREid Connect to Keycloak.

## Installation

Install from git and configure

```bash
git clone https://github.com/rciam/rciam-client-migration.git
cd rciam-client-migration
cp example-config.py config.py
vi config.py
```

Create a Python virtualenv, install dependencies, and run the script

```bash
apt install python3-virtualenv
virtualenv -p python3 .venv
source .venv/bin/activate
(venv) pip3 install -r requirements.txt
(venv) python main.py
🍺
```

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.

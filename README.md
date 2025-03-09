# from-sigma-to-deephunter
## Overview

This repository contains the `sigma-to-deephunter.py` script, which downloads and processes SIGMA rules from a specified GitHub repository.
The script extracts PowerQuery and SIGMA rule details and updates a JSON file with this information.

Source of Sigma rules is the official SigmaHQ repository https://github.com/SigmaHQ/sigma.

Translation from Sigma to PowerQuery is made by GitHub Actions on https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/.

DeepHunter is a tool with WebGUI to automatize execution of threat hunting queries in daily campaigns and collection of daily statistics (number of matching events, number of matching endpoints, etc). Repository is https://github.com/sebastiendamaye/deephunter and documentation is available on https://deephunter.readthedocs.io/en/latest/.

## Requirements
To install the necessary dependencies, ensure you have `pip` installed and run:

```sh
pip install -r requirements.txt
```

The `requirements.txt` file includes the following dependencies:
- gitpython
- pyyaml
- sigma-cli

## Installation and Usage
1. Clone the repository:
    ```sh
    git clone https://github.com/wikijm/from-sigma-to-deephunter.git
    cd from-sigma-to-deephunter
    ```

2. Install the required dependencies as mentioned above.

3. Run the script:
    ```sh
    python sigma-to-deephunter.py
    ```

The script will:
- Download the specified GitHub repository zip file.
- Extract `.md` files (excluding `README.md`).
- Extract PowerQuery and SIGMA rule details from these files.
- Update the `query.json` file with the extracted information.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

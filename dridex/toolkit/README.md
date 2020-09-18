                            _____       _         _           _         
         /\                / ____|     | |       | |         | |        
        /  \   _ __  _ __ | |  __  __ _| |_ ___  | |     __ _| |__  ___ 
       / /\ \ | '_ \| '_ \| | |_ |/ _` | __/ _ \ | |    / _` | '_ \/ __|
      / ____ \| |_) | |_) | |__| | (_| | ||  __/ | |___| (_| | |_) \__ \
     /_/    \_\ .__/| .__/ \_____|\__,_|\__\___| |______\__,_|_.__/|___/
              | |   | |                                                 
              |_|   |_|    

# Dridex

This repository contains files related to Dridex malware analysis.

## Analysis Tookit

This script automates the IOC extraction from the Dridex loader, able to:

- Extract Botnet ID;
- Extract C2 IP Addresses;
- Decrypt Strings;
- Decrypt Network Communication.

### Options

- `-f (--file)`: Unpacked Dridex sample to parse.
- `-a (--all)`: Runs C2 extractor and strings decrypter.
- `-n (--network_key)`: RC4 key to decrypt network data.
- `-c (--c2)`: Extracts Botnet ID and C2 server.
- `-s (--strings)`: Decrypt strings.
- `-v (--verbose)`: Prints output in console.

### Installation

Make sure to install the requirements prior script usage:

`pip install -r requirements.txt`

### Examples

- Running everything (botnet ID, C2 IPs, decrypted strings):

`python dridex_analysis.py -v -f loader.bin -a`

- Extracting the Botnet ID and C2 addresses from Dridex loader:

`python dridex_analysis.py -v -f loader.bin -c`

- Decrypting Dridex strings:

`python dridex_analysis.py -v -f loader.bin -s`

- Decrypting Dridex network data:

_Observation: The RC4 key can be obtained using the "-s" option._

`python dridex_analysis.py -v -f network_data.bin -n rc4_decryption_key`
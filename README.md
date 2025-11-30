# [OverTheWire](https://overthewire.org/) Automation Script

Just a simple Powershell script to provide some helpful automation when going through the levels
of wargames in [OverTheWire](https://overthewire.org/).

## Usage

    PS> ./Play-Wargame.ps1 bandit

where `bandit` can be any wargame whose information is provided in wargames.json.

The script works by creating a subdirectory for the wargame in the script root dir where it stores
the level passwords and other necessary files as you go through the wargame. When finished with a
wargame, this directory can be compressed for proof of completion.

## Bugs

This was written pretty quickly, so it's very buggy; pull requests for fixes and features
are very welcome.

# EZSCRIPT
> Windows Hardening made EZ | Ethan Michalak

## Set up
*Open powershell with administrative privileges*

Type:
```sh
set-executionpolicy remote-signed
```
Script Changes:
```sh
Adjust $user variable in the script to whatever user you are currently logged into on the machine

Comment out any necessary services or necessary features so they wont be stopped/disabled
```
Files:
```sh
Add the Win10Firewall.wfw file to the Desktop of the user running the script
```


## Running it
*Open powershell with administrative privileges*

Once inside the directory that houses the script type:
```sh
./ezscript.ps1
```
Select the first option and then the second or third 

*Running the second or third option before the first will brake the script!*

## Usage
This is a very useful script for sysadmins or IT professionals looking to secure a windows machine in a very easy fashion.  This Script will create a directory on the desktop called scripterino which houses all the files created.
This script covers all of the following:
* All types of files and categorizes them
* Users
    * Makes a list of all users and groups on the machine
    * Disables Guest and Admin account and renames them
    * Sets every users password on the machine to 'K3wLP@SsW0rd'
* Policies
    * Account policies and Local Policies
* Makes a file of all shares on the machine
* Flushes DNS file
* Grabs hosts file
* Features
    * Force disables all unnecessary features
* Makes a file with all processes that exceed 2000 Megabytes
* Firewall
    * Force turns on firewall
    * Imports firewall configuration file with secure settings
    * Adds custom rules for security
* Sets network profile to public so file sharing, device discovery, etc. is disabled
* Registry keys are adding to do the following
    * disable remote desktop
    * set automatic updates
    * restrict CD ROM drive
    * disable remote access to floppy disk
    * clear page file
    * no printer drivers
    * auditing to LSASS.exe
    * Enable LSA protection
    * Limit use of blank passwords
    * Auditing access of Global System Objects
    * Auditing Backup and Restore
    * Restrict Anonymous Enumeration
    * Disable storage of domain passwords
    * Disable Anonymous User Everyone permissions
    * Allow Machine ID for NTLM
    * Do not display last user on logon
    * Enables UAC
    * Set UAC to high
    * Enable Installer Detection
    * Max password age
    * disable machine account password changes
    * require strong session key
    * require sign/seal
    * sign channel
    * seal channel
    * set idel time to 45 minutes
    * require security signature
    * enable security signature
    * clear null session pipes
    * restrict anonymous user access to named pipes and shares
    * encrypt smb passwords
    * clear remote registry paths
    * clear sub paths
    * enable smart screen for IE8
    * enable smart screen for IE9 and up
    * disable IE password caching
    * warn users if website has a bad certificate
    * warn users if website redirects
    * enable do not track
    * show hidden files
    * show super hidden files
    * disable dump file creation
    * disable autoruns
    * enable internet explorer phishing filter
    * block macros and other content execution
    * enables window defender
* Services
    * Disables all unnecessary services 
    * Enables all necessary services such as windows updates

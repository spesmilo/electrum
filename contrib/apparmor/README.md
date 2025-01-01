# Electrum AppArmor Profiles
AppArmor is a Mandatory Access Control (MAC) system which confines programs to a limited set of resources.
AppArmor confinement is provided via profiles loaded into the kernel.

## Installation

Copy the AppArmor profile from `contrib/apparmor/apparmor.d/` to `/etc/apparmor.d/`:
```
sudo cp -R -L contrib/apparmor/apparmor.d/* /etc/apparmor.d
```
Reload the AppArmor profiles to apply the changes:
```
sudo systemctl reload apparmor
```
Verify that the profile is loaded:
```
sudo apparmor_status
```
Look for the entry corresponding to `electrum`

## Usage 
After installing the AppArmor profile, electrum will be restricted to the permissions specified in the profile.

## Compatibility
The help tab may not function as expected as browser permissions can be tricky (Tarball Binaries)

These AppArmor profiles have been tested on the following operating systems:
```
Debian 12
Ubuntu 23.10
Kali Linux 6.6
```

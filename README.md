[![Inline docs](http://inch-ci.org/github/JayBeeDe/xen-backup-VMs.svg?branch=master)](http://inch-ci.org/github/JayBeeDe/xen-backup-VMs) [![HitCount](http://hits.dwyl.com/JayBeeDe/xen-backup-VMs.svg)](http://hits.dwyl.com/JayBeeDe/xen-backup-VMs)

Version | Date | Author | Description
------------- | ------------- | ------------- | -------------
0.4 | 27/03/2020 | @Jean-Baptiste DELON | First Release

# Description

Python script that backups VMs from a remote xen hypervisor to a remote (not mounted locally) samba share.

If enable, a report with all the logs can be send at the end of the script execution.

Script philosophy is :
- local script but remote hypervisor and remote 2 samba share
- no bash command calls
- use the XenAPI python library and existing http_action function (uses the "requests" python library) to download / upload a VM backup
- no use of ssh
- no mount of samba share : use the python samba client library instead.

VM Restoration is not implemented yet (despite the existance of the ACTION_MODE setting)...
You are welcome to implement it by following the script philosophy.

# Thanks

Initially developped by [Linagora](https://linagora.com/), this script has been released on GitHub under the [GNU General Public License version 3](LICENSE).

<p align="center">
  <a href="https://linagora.com/"><img alt="Linagora" src="https://upload.wikimedia.org/wikipedia/commons/thumb/5/54/Linagora-logo.png/420px-Linagora-logo.png"></a>
</p>

# Documentation

[Documentation Page](https://github.com/JayBeeDe/xen-backup-VMs/wiki)

# Contact

If you have questions, troobleshoutings or improvement proposals which ONLY DIRECTLY CONCERN this script, please contact me :

>27-03-2020 | Jean-Baptiste DELON [Issues](https://github.com/JayBeeDe/xen-backup-VMs/issues)

>Copyleft 2020
# xen-backup-VMs
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
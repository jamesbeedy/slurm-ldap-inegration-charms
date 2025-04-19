# Charmed NFS Homedir Server Operator
This charm should be used in conjuction with the openldap-operator and sssd-operator to provide nfs home dirs.


Notes
* This charm does not work with containers.

## Build the homedir-server operator charm
Build this charm using `charmcraft`.
```bash
$ charmcraft pack
Packed homedir-server_amd64.charm
```

Deploy the charm to virtual-machine using the LXD provider.
```bash
$ juju deploy ./homedir-server_amd64.charm --constraints "virt-type=virtual-machine cores=2 mem=2G" --base ubuntu@24.04
Located local charm "homedir-server", revision 0
Deploying "homedir-server" from local charm "homedir-server", revision 0 on ubuntu@24.04/stable
```

# Charmed SSSD Operator
This charm installs and manages sssd and autofs and is intended to be used with the openldap operator charm.


## Getting Started

Build Charm
```bash
charmcraft pack
```

Deploy Charm
```bash
juju deploy ./sssd_amd64.charm
``` 

Relate to openldap operator.
```bash
juju relate sssd openldap
````

Relate to arbitrary host to enable ldap user management.
```bash
juju deploy ubuntu --constraints "virt-type=virtual-machine cores=1 mem=1G"

juju relate sssd ubuntu
```

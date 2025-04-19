# SLURM + LDAP Integration Charms

This repository comprises three charmed services:
* [openldap](./charms/openldap)
* [sssd](./charms/sssd)
* [nfs-home](./charms/nfs-home)

These three services work together to provide federated users and automount homedirs for the slurm cluster.

## Getting Started
Build the charms in this repo, then deploy them alongside the slurm charms using the `bundle.yaml`.

### Build the Charms
This project uses [`uv`](https://docs.astral.sh/uv/) in combination with [`just`](https://github.com/casey/just)
to drive [`charmcraft`](https://canonical-charmcraft.readthedocs-hosted.com/en/stable/) to build the charms in lxd containers.

Once you have `charmcraft`, `lxd`, `just`, and `uv` installed you are ready to build. 

Build the charms using the following command.
```bash
just repo build
```


### Deploy the [`bundle.yaml`](./bundle.yaml)
Use [`juju`](https://juju.is/) to deploy the `bundle.yaml` file.

Note: `juju` uses the local `lxd` hypervisor to orchestrate services, so ensure you have that [setup](https://canonical.com/microstack/docs/bootstrap-lxd-based-juju-controller).

Assuming you have a bootstrapped lxd controller handy, add the model to house the infrastructure and deploy the bundle.
```bash
juju add-model ldap-testing

juju deploy ./bundle.yaml
```

### Access the System
This deployment has been seeded with 2 users in ldap, respectively, user1 and user2.

To login to the system as one of these users, you must first ensure that the home directory has been created on the nfs home server, then you can ssh
into the machine as the ldap user and have your `/home` directory mounted on every node in the cluster.

#### 1) Make sure a homedirectory exists
```bash
$ juju exec --unit nfs-home/0 "sudo -iu user1"
Creating directory '/home/user1'.
```

#### 2) Move the test ssh key and chmod/chown
```bash
cp charms/openldap/notes/id_rsa_ldap ~/.ssh/id_rsa_ldap
chown $USER ~/.ssh/id_rsa_ldap
chmod 600 ~/.ssh/id_rsa_ldap
```

#### 3) Run node-configured to prepare the cluster
```bash
juju run slurmd/leader node-configured
```

#### 4) SSH into the sackd/0 as user1
```bash
sackd_ip=`juju status sackd --format json   | jq -r '.applications.sackd.units[]["public-address"]'`
ssh -i ~/.ssh/id_rsa_ldap user1@$sackd_ip
```

#### 5) Run a job as user1 from the sackd unit.
Use slurm to validate our work.
```bash
user1@juju-e0196c-4:~$ srun -pslurmd hostname
juju-e0196c-6

user1@juju-e0196c-4:~$ srun -pslurmd echo $UID
5556

user1@juju-e0196c-4:~$ srun -pslurmd echo $USER
user1

user1@juju-e0196c-4:~$ srun -pslurmd pwd
/home/user1

user1@juju-e0196c-4:~$ srun -pslurmd mount | grep home
auto.home on /home type autofs (rw,relatime,fd=7,pgrp=16679,timeout=300,minproto=5,maxproto=5,indirect,pipe_ino=58346)
10.240.222.222:/home/user1 on /home/user1 type nfs4 (rw,relatime,vers=4.2,rsize=262144,wsize=262144,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.240.222.142,local_lock=none,addr=10.240.222.222)
```



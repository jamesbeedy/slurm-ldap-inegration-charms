# User Federation Charmed Operators

#### User Federation + Automount Homes for Slurm Charms + Jupyterhub

This repository comprises four charmed services:
* [openldap](./charms/openldap)
* [sssd](./charms/sssd)
* [nfs-home](./charms/nfs-home)
* [jupyterhub](./charms/jupyterhub)

And two docker services (using [docker-compose.yml](./docker-compose.yml)):
* [keycloak](https://keycloak.org)
* [phpldapadmin](https://github.com/leenooks/phpLDAPadmin)

These three services work together to provide federated users and automount homedirs for the slurm cluster + Jupyterhub.

## Getting Started
Build the charms in this repo, then deploy them alongside the slurm charms using the `bundle.yaml`.

### Build the Charms
This project uses [`uv`](https://docs.astral.sh/uv/) in combination with [`just`](https://github.com/casey/just)
to drive [`charmcraft`](https://canonical-charmcraft.readthedocs-hosted.com/en/stable/) to build the [charms](https://juju.is/charms-architecture) in [`lxd`](https://canonical.com/lxd) containers.

Once you have `charmcraft`, `lxd`, `just`, and `uv` installed you are ready to build.

Build the charms using the following command.
```bash
just repo build
```


### Deploy the Bundle
Use [`juju`](https://juju.is/) to deploy the [`bundle.yaml`](./bundle.yaml) file.

Note: `juju` uses the local `lxd` hypervisor to orchestrate services. Ensure juju and lxd are [setup](https://canonical.com/microstack/docs/bootstrap-lxd-based-juju-controller).

Assuming you have a bootstrapped lxd controller handy, add the model to house the infrastructure and deploy the bundle.
```bash
juju bootstrap localhost

juju add-model ldap-testing localhost

sed -i "s|\(keycloak-url: http://\)[0-9.]\+|\1$(hostname -I | awk '{print $1}')|" bundle.yaml

juju deploy ./bundle.yaml
```

Run `juju status --watch 1s --color` to watch the infrastructure spin up.

When the deployment is finished it should resemble:
```bash
Model         Controller           Cloud/Region         Version  SLA          Timestamp
ldap-testing  localhost-localhost  localhost/localhost  3.6.5    unsupported  22:01:39Z

App             Version          Status  Scale  Charm              Channel      Rev  Exposed  Message
jupyterhub                       active      1  jupyterhub                        0  no       http://192.168.7.143:8000
jupyterhub-nfs                   active      1  filesystem-client  latest/edge   15  no       Mounted filesystem at `/jupyterhub-nfs`.
mysql           8.0.41-0ubun...  active      1  mysql              8.0/stable   366  no     
nfs-home                         active      1  nfs-home                          0  no     
openldap                         active      1  openldap                          0  no       Serving: dc=vantage
sackd           23.11.4-1.2u...  active      1  sackd              latest/edge   18  no        
slurmctld       23.11.4-1.2u...  active      1  slurmctld          latest/edge  100  no     
slurmd          23.11.4-1.2u...  active      1  slurmd             latest/edge  121  no        
slurmdbd        23.11.4-1.2u...  active      1  slurmdbd           latest/edge   92  no     
sssd-autofs                      active      3  sssd                              0  no       
sssd-no-autofs                   active      1  sssd                              0  no     

Unit                 Workload  Agent  Machine  Public address  Ports           Message
jupyterhub/0*        active    idle   4        192.168.7.143                   http://192.168.7.143:8000
mysql/0*             active    idle   2        192.168.7.139   3306,33060/tcp  Primary
nfs-home/0*          active    idle   0        192.168.7.141           
  sssd-no-autofs/0*  active    idle            192.168.7.141           
openldap/0*          active    idle   1        192.168.7.137                   Serving: dc=vantage
sackd/0*             active    idle   4        192.168.7.143                        
  sssd-autofs/2      active    idle            192.168.7.143                       
slurmctld/0*         active    idle   5        192.168.7.140           
  sssd-autofs/0*     active    idle            192.168.7.140                           
slurmd/0*            active    idle   6        192.168.7.142                       
  jupyterhub-nfs/0*  active    idle            192.168.7.142                   Mounted filesystem at `/jupyterhub-nfs`.
  sssd-autofs/1      active    idle            192.168.7.142                       
slurmdbd/0*          active    idle   3        192.168.7.138           

Machine  State    Address        Inst id        Base          AZ  Message
0        started  192.168.7.141  juju-571140-0  ubuntu@24.04      Running
1        started  192.168.7.137  juju-571140-1  ubuntu@24.04      Running
2        started  192.168.7.139  juju-571140-2  ubuntu@22.04      Running
3        started  192.168.7.138  juju-571140-3  ubuntu@24.04      Running
4        started  192.168.7.143  juju-571140-4  ubuntu@24.04      Running
5        started  192.168.7.140  juju-571140-5  ubuntu@24.04      Running
6        started  192.168.7.142  juju-571140-6  ubuntu@24.04      Running
```

### Access the System

#### 1) Run node-configured to prepare the cluster
```bash
juju run slurmd/leader node-configured
```

#### 2) Create a user
```bash
juju run openldap/leader add-user username="johndoe" password="password" uid="'5999'" ssh-key="$(cat ~/.ssh/id_rsa.pub)" email="johndoe@example.com"
```

#### 3) Make sure a homedirectory exists
```bash
juju exec --unit nfs-home/0 "sudo -iu johndoe"
```

#### 4) SSH into the sackd/0 as johndoe
```bash
juju ssh johndoe@sackd/0
```

#### 5) Use slurm to validate our work
```bash
srun hostname

srun echo $UID

srun echo $USER

srun pwd

srun mount | grep home
```

#### Deploy Keycloak and integrate with LDAP
Prepare the ldap server cert to be added to the keycloak truststore.
```bash
juju ssh --quiet --pty=false openldap/leader cat /etc/ldap/ldap01_slapd_cert.pem > .extras/cert.pem
```

```bash
JUPYTERHUB_CLIENT_SECRET=`juju config jupyterhub oidc-client-secret` \
JUPYTERHUB_URL=`juju run jupyterhub/leader get-jupyterhub-url --quiet --format=json  | jq .[].results.url | xargs -I % -0 python3 -c 'print(%)'` \
LDAP_HOST=`juju status --format json | jq -r '.applications.openldap.units[]["public-address"]'` \
LDAP_ADMIN_PASSWORD=`juju run openldap/leader get-admin-password --quiet | awk '{print $2}' | tr -d "\n"` \
    docker compose up -d
```

Run the following command to get the jupyterhub url and then visit the url in your browser. Login with the johndoe username and password we created above.
```bash
juju run jupyterhub/leader get-jupyterhub-url --quiet --format=json  | jq .[].results.url | xargs -I % -0 python3 -c 'print(%)'
```


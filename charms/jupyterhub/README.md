# Charmed Jupyterhub Slurm Operator
This charm is a POC for jupyterhub integration with the [slurm-charms](https://github.com/charmed-hpc/slurm-charms).

The charmed operator installs an nfs-server, jupyterhub server, and tailscale funnel on top of a working slurm deployment
to provide jupyterhub notebook servers to system level users.

## Getting Started Example

This example makes use of juju, lxd, charmcraft, and tailscale. It is expected that
a bootstrapped juju/lxd controller already exist.

Given that a juju controller is already bootstrapped on lxd:

1) Build the charm
2) Add juju model
3) Deploy the bundle
4) Configure access by adding tailscale auth-key

### 1) Build the charm
Clone this repository and execute the `charmcraft pack` command to build the charm.

```bash
git clone git@github.com:charmed-hpc/charm-jupyterhub-slurm-operator
cd charm-jupyterhub-slurm-operator/

charmcraft pack
```

### 2) Add a model
Add the juju model with `juju add-model` command.

```bash
juju add-model jupyterhub-testing localhost
```

### 3) Deploy slurm + jupyterhub
Deploy the `bundle.yaml` file.

```bash
juju deploy ./bundle.yaml
```

Watch the deployment spin up: `juju status --watch 1s --color`


Once settled, the deployed budle will resemble:
```bash
Model               Controller           Cloud/Region         Version  SLA          Timestamp
jupyterhub-testing  localhost-localhost  localhost/localhost  3.5.7    unsupported  15:01:13Z

App             Version          Status   Scale  Charm              Channel      Rev  Exposed  Message
jupyterhub                       blocked      1  jupyterhub                        0  no       Set 'tailscale-auth-key-secret-id' to continue
.
jupyterhub-nfs                   active       1  filesystem-client  latest/edge   15  no       Mounted filesystem at `/jupyterhub-nfs`.
mysql           8.0.41-0ubun...  active       1  mysql              8.0/edge     368  no    
sackd           23.11.4-1.2u...  active       1  sackd              latest/edge   17  no       
slurmctld       23.11.4-1.2u...  active       1  slurmctld          latest/edge   99  no       
slurmd          23.11.4-1.2u...  active       1  slurmd             latest/edge  120  no       
slurmdbd        23.11.4-1.2u...  active       1  slurmdbd           latest/edge   91  no       

Unit                 Workload  Agent  Machine  Public address  Ports           Message
jupyterhub/0*        blocked   idle   4        10.240.222.248                  Set 'tailscale-auth-key-secret-id' to continue.
mysql/0*             active    idle   3        10.240.222.69   3306,33060/tcp  Primary
sackd/0*             active    idle   4        10.240.222.248                         
slurmctld/0*         active    idle   1        10.240.222.36                       
slurmd/0*            active    idle   0        10.240.222.112                      
  jupyterhub-nfs/0*  active    idle            10.240.222.112                  Mounted filesystem at `/jupyterhub-nfs`.
slurmdbd/0*          active    idle   2        10.240.222.153                   

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.240.222.112  juju-b8c06f-0  ubuntu@24.04      Running
1        started  10.240.222.36   juju-b8c06f-1  ubuntu@24.04      Running
2        started  10.240.222.153  juju-b8c06f-2  ubuntu@24.04      Running
3        started  10.240.222.69   juju-b8c06f-3  ubuntu@22.04      Running
4        started  10.240.222.248  juju-b8c06f-4  ubuntu@24.04      Running
```

Once the bundle settles, run the following commands.
```bash
juju run slurmd/0 node-configured

for i in slurmd sackd slurmctld; do
    juju ssh $i/leader "echo 'ubuntu:ubuntu' | sudo chpasswd";
done;
```

### 4) Configure the tailscale-auth-key
The last step is to configure the tailscale-auth-key to provide access to jupyterhub via your tailnet.

If you don't already have a tailscale-auth-key, login to your tailscale account and generate one at
[https://login.tailscale.com/admin/settings/keys](https://login.tailscale.com/admin/settings/keys).

Once you have generated your tailscale-auth-key, create the model secret and configure the jupyterhub charm like so.
```bash
# juju add-secret tailscale-auth-key tailscale-auth-key=tskey-auth-kHZ4nFsxbr11CNTRL*****
juju add-secret tailscale-auth-key tailscale-auth-key=<ts-auth-key-obtained-from-your-tailscale-admin-ui>

juju grant-secret tailscale-auth-key jupyterhub

secret_id=`juju show-secret tailscale-auth-key --format json | jq -r keys[]`
juju config jupyterhub tailscale-auth-key-secret-id="secret:$secret_id"
```

### 5) Access the jupyterhub gui via tailnet
Run the following command to retrieve the jupyterhub url.
```bash
juju run jupyterhub/leader get-jupyterhub-url \
    --quiet --format=json  | jq .[].results.url | xargs -I % -0 python3 -c 'print(%)'
```

Open the jupyterhub url in your browser and login with username: ubuntu, password: ubuntu.

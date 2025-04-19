# Copyright 2025 Vantage Compute Corp
# See LICENSE file for licensing details.

"""JupyterHub Configuration File."""

import os
from oauthenticator.generic import GenericOAuthenticator

# Environment Variables
ip_address = os.environ.get("IP_ADDRESS")
hub_url = f"http://{ip_address}:8000"

keycloak_url = ""
oidc_client_secret = ""

if (tailscale_dns_name := os.environ.get("TAILSCALE_DNS_NAME")) is not None:
    hub_url = tailscale_dns_name

admin = os.environ.get("JUPYTERHUB_ADMIN")

# Set JupyterHub service URL
os.environ["JUPYTERHUB_SERVICE_URL"] = f"http://{ip_address}:8000"

# Base config
c = get_config()

# -----------------------------------------------------------------------------
# JupyterHub Core Configuration
# -----------------------------------------------------------------------------
c.JupyterHub.hub_ip = ip_address
c.JupyterHub.hub_port = 8080
c.JupyterHub.hub_connect_port = 8080

c.JupyterHub.bind_url = 'http://:8000'
c.JupyterHub.public_url = f"{hub_url}/hub"

c.JupyterHub.hub_connect_url = f"http://{ip_address}:8080"
c.JupyterHub.hub_connect_ip = ip_address

c.JupyterHub.allow_named_servers = True
c.JupyterHub.reset_db = True
c.JupyterHub.cookie_secure = False
c.JupyterHub.cookie_path = "/hub/login"
c.JupyterHub.spawner_class = "batchspawner.SlurmSpawner"


if (keycloakurl := os.environ.get("KEYCLOAK_URL")) is not None:
    keycloak_url = keycloakurl

if (client_secret := os.environ.get("OIDC_CLIENT_SECRET")) is not None:
    oidc_client_secret = client_secret

if all([keycloak_url, oidc_client_secret]):
    c.JupyterHub.authenticator_class = GenericOAuthenticator

    # GenericOAuthenticator Config
    os.environ['OAUTH2_TOKEN_URL'] = f"{keycloak_url}/realms/vantage/protocol/openid-connect/token"
    os.environ['OAUTH2_AUTHORIZE_URL'] = f"{keycloak_url}/realms/vantage/protocol/openid-connect/auth"
    os.environ['OAUTH2_USERDATA_URL'] = f"{keycloak_url}/realms/vantage/protocol/openid-connect/userinfo"
    os.environ['OAUTH2_USERNAME_KEY'] = 'preferred_username'
    os.environ['OAUTH2_TLS_VERIFY'] = '0'
    os.environ['OAUTH_TLS_VERIFY'] = '0'
    
    c.GenericOAuthenticator.login_service = "KeyCloak"
    c.GenericOAuthenticator.client_id = "jupyter"
    c.GenericOAuthenticator.client_secret = f"{oidc_client_secret}"
    c.GenericOAuthenticator.token_url = os.environ['OAUTH2_TOKEN_URL']
    c.GenericOAuthenticator.userdata_url = os.environ['OAUTH2_USERDATA_URL']
    c.GenericOAuthenticator.oauth_callback_url = f"http://{ip_address}:8000/hub/oauth_callback"
    c.GenericOAuthenticator.userdata_params = {"state": "state"}
    c.GenericOAuthenticator.userdata_method = "GET"
    c.GenericOAuthenticator.username_claim = "preferred_username"
    c.GenericOAuthenticator.scope = ["openid"]
    c.GenericOAuthenticator.auto_login = True
    c.GenericOAuthenticator.tls_verify = False
    c.GenericOAuthenticator.allow_all = True


# Authenticator Config
if admin:
    c.Authenticator.admin_users = [admin]

c.Authenticator.allow_all = True
c.NativeAuthenticator.open_signup = True

# -----------------------------------------------------------------------------
# Proxy Configuration
# -----------------------------------------------------------------------------
c.ConfigurableHTTPProxy.api_token = "test"
c.ConfigurableHTTPProxy.api_url = f"http://{ip_address}:8081"

# -----------------------------------------------------------------------------
# Notebook Configuration
# -----------------------------------------------------------------------------
c.NotebookApp.allow_origin = "*"

# -----------------------------------------------------------------------------
# Spawner Configuration
# -----------------------------------------------------------------------------
c.Spawner.environment.update(
    {
        "JUPYTER_PREFER_ENV_PATH": "0",
    }
)
c.Spawner.args = ["--NotebookApp.allow_origin=*"]
c.Spawner.default_url = "/lab"
c.Spawner.notebook_dir = "~"
c.Spawner.start_timeout = 300
c.Spawner.http_timeout = 300
c.Spawner.debug = True

# -----------------------------------------------------------------------------
# BatchSpawner - SlurmSpawner Configuration
# -----------------------------------------------------------------------------
c.SlurmSpawner.batch_script = """#!/bin/bash
#SBATCH --output={{homedir}}/jupyterhub_slurmspawner_%j.log
#SBATCH --job-name=spawner-jupyterhub
#SBATCH --chdir={{homedir}}
#SBATCH --export={{keepvars}}
#SBATCH --get-user-env=L
{% if partition  %}#SBATCH --partition={{partition}}{% endif %}
{% if runtime    %}#SBATCH --time={{runtime}}{% endif %}
{% if memory     %}#SBATCH --mem={{memory}}{% endif %}
{% if gres       %}#SBATCH --gres={{gres}}{% endif %}
{% if nprocs     %}#SBATCH --cpus-per-task={{nprocs}}{% endif %}
{% if reservation%}#SBATCH --reservation={{reservation}}{% endif %}
{% if options    %}#SBATCH {{options}}{% endif %}

set -euo pipefail

trap 'echo SIGTERM received' TERM
{{prologue}}
srun /jupyterhub-nfs/venv/bin/batchspawner-singleuser /jupyterhub-nfs/venv/bin/jupyterhub-singleuser
echo "jupyterhub-singleuser ended gracefully"
{{epilogue}}
"""

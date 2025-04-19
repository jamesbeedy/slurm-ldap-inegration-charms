# Copyright 2025 Vantage Compute Corp
# See LICENSE file for licensing details.

"""JupyterhubOps."""

import subprocess
import logging

from pathlib import Path
from shutil import copy2, rmtree
import charms.operator_libs_linux.v0.apt as apt
from exceptions import JupyterhubOpsError

logger = logging.getLogger(__name__)


class JupyterhubOps:
    """Jupyterhub ops."""

    _PACKAGE_NAME = "jupyterhub"
    _SYSTEMD_SERVICE_NAME = "jupyterhub"
    _SYSTEMD_BASE_PATH = Path("/usr/lib/systemd/system")
    _SYSTEMD_SERVICE_ALIAS = f"{_PACKAGE_NAME}.service"
    _SYSTEMD_SERVICE_FILE = _SYSTEMD_BASE_PATH / _SYSTEMD_SERVICE_ALIAS
    _VENV_DIR = Path("/jupyterhub-nfs/venv")
    _PIP_CMD = _VENV_DIR.joinpath("bin", "pip3").as_posix()
    _PYTHON_CMD = Path("/usr/bin/python3")

    def install(self):
        """Install jupyterhub, deps and reqs."""
        try:
            # Run `apt-get update`
            apt.update()
            apt.add_package(["python3.12-venv"])
        except apt.PackageNotFoundError as e:
            logger.error(
                f"{self._package_name} not found in package cache or on system"
            )
            raise JupyterhubOpsError(e)
        except apt.PackageError as e:
            logger.error(
                f"Could not install {self._package_name}. Reason: %s", e.message
            )
            raise JupyterhubOpsError(e)

        # Create the virtualenv and ensure pip is up to date.
        self._create_venv_and_ensure_latest_pip()
        # Install jupyterhub
        self._install_jupyterhub()
        # Install additional dependencies post.
        self._install_extra_deps_post()
        # Provision the jupyterhub systemd service.
        self._setup_config()
        self._setup_systemd()

    def configure(
        self,
        ingress_address,
        oidc_client_secret=None,
        keycloak_url=None,
        tailscale_uri=None,
    ) -> None:
        """Install jupyterhub defaults file."""
        default_str = f"IP_ADDRESS={ingress_address}\n"
        default_str += "JUPYTERHUB_ADMIN=ubuntu\n"
        if tailscale_uri is not None:
            default_str += f"TAILSCALE_DNS_NAME={tailscale_uri}\n"
        if oidc_client_secret is not None:
            default_str += f"OIDC_CLIENT_SECRET={oidc_client_secret}\n"
        if keycloak_url is not None:
            default_str += f"KEYCLOAK_URL={keycloak_url}\n"

        Path("/etc/default/jupyterhub").write_text(default_str)

    def get_version_info(self):
        """Show version and info about jupyterhub."""
        cmd = [self._PIP_CMD, "show", self._PACKAGE_NAME]

        out = subprocess.check_output(cmd, env={}).decode().strip()

        return out

    def systemctl(self, operation: str):
        """
        Run systemctl operation for the service.
        """
        cmd = [
            "systemctl",
            operation,
            self._SYSTEMD_SERVICE_NAME,
        ]
        try:
            subprocess.call(cmd)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running {' '.join(cmd)} - {e}")

    def uninstall(self):
        """
        Remove the things we have created.
        """
        # Stop and disable the systemd service.
        self.systemctl("stop")
        self.systemctl("disable")
        # Remove files and dirs created by this charm.
        if self._SYSTEMD_SERVICE_FILE.exists():
            self._SYSTEMD_SERVICE_FILE.unlink()
        subprocess.call(["systemctl", "daemon-reload"])
        rmtree(self._VENV_DIR.as_posix())

    def _create_venv_and_ensure_latest_pip(self):
        """Create the virtualenv and upgrade pip."""

        # Create the virtualenv
        create_venv_cmd = [
            self._PYTHON_CMD,
            "-m",
            "venv",
            "--system-site-packages",
            self._VENV_DIR.as_posix(),
        ]
        logger.debug(f"## Creating virtualenv: {create_venv_cmd}")
        subprocess.call(create_venv_cmd, env=dict())
        logger.debug("## jupyterhub virtualenv created")

        # Ensure we have the latest pip
        upgrade_pip_cmd = [
            self._PIP_CMD,
            "install",
            "--upgrade",
            "pip",
        ]
        logger.debug(f"## Updating pip: {upgrade_pip_cmd}")
        subprocess.call(upgrade_pip_cmd, env=dict())
        logger.debug("## Pip upgraded")

    def _setup_config(self) -> None:
        """Provision the jupyterhub systemd service."""
        copy2(
            "./templates/jupyterhub_config.py",
            "/jupyterhub-nfs/etc/jupyterhub_config.py",
        )

    def _setup_systemd(self):
        """Provision the jupyterhub systemd service."""
        copy2(
            "./templates/jupyterhub.service",
            self._SYSTEMD_SERVICE_FILE.as_posix(),
        )

        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["systemctl", "enable", self._SYSTEMD_SERVICE_ALIAS])

    def _install_extra_deps_post(self):
        """Install additional dependencies."""
        cmd = [
            self._PIP_CMD,
            "install",
            "-I",
            "jupyterlab",
            "notebook",
            "batchspawner",
            "oauthenticator",
            "jupyter-ai[all]",
            "jupyterlab-unfold",
            "jupyterlab-nvdashboard",
            "configurable-http-proxy",
        ]
        logger.debug(f"## Installing extra dependencies: {cmd}")
        try:
            subprocess.call(cmd, env=dict())
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running {' '.join(cmd)} - {e}")
            raise e

    def _install_jupyterhub(self):
        """Install the jupyterhub package."""
        cmd = [
            self._PIP_CMD,
            "install",
            "-I",
            "-U",
            self._PACKAGE_NAME,
        ]
        logger.debug(f"## Installing jupyterhub: {cmd}")
        try:
            subprocess.call(cmd, env=dict())
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running {' '.join(cmd)} - {e}")
            raise e

    def start(self):
        """Starts the jupyterhub"""
        self.systemctl("start")

    def stop(self):
        """Stops the jupyterhub"""
        self.systemctl("stop")

    def restart(self):
        """Restart the jupyterhub"""
        self.systemctl("restart")

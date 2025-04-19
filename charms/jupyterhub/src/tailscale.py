# Copyright 2025 Vantage Compute Corp
# See LICENSE file for licensing details.

"""Tailscale."""

import json
import logging
import subprocess
from pathlib import Path

from exceptions import TailscaleError
import charms.operator_libs_linux.v0.apt as apt

logger = logging.getLogger()


class Tailscale:
    """Facilitate tailscale package lifecycle ops."""

    _package_name = "tailscale"
    _tailscale_apt_list_tmpl = Path("./templates/tailscale.list")
    _tailscale_apt_gpg_tmpl = Path("./templates/tailscale-archive-keyring.gpg")
    _tailscale_apt_list = Path("/etc/apt/sources.list.d/tailscale.list")
    _tailscale_apt_gpg = Path("/usr/share/keyrings/tailscale-archive-keyring.gpg")

    def install(self) -> None:
        """Install the tailscale package using lib apt."""

        self._tailscale_apt_list.write_text(self._tailscale_apt_list_tmpl.read_text())
        self._tailscale_apt_gpg.write_bytes(self._tailscale_apt_gpg_tmpl.read_bytes())

        # Install the tailscale package.
        try:
            apt.update()
            apt.add_package(self._package_name)
        except apt.PackageNotFoundError as e:
            logger.error(
                f"{self._package_name} not found in package cache or on system"
            )
            raise TailscaleError(e)
        except apt.PackageError as e:
            logger.error(
                f"Could not install {self._package_name}. Reason: %s", e.message
            )
            raise TailscaleError(e)

    def uninstall(self) -> None:
        """Uninstall the tailscale package using libapt."""
        if apt.remove_package(self._package_name):
            logger.info(f"{self._package_name} removed from system.")
        else:
            logger.error(f"{self._package_name} not found on system")

        for tailscale_path in [self._tailscale_apt_list, self._tailscale_apt_gpg]:
            if tailscale_path.exists():
                tailscale_path.unlink()

    def up(self, auth_key: str) -> None:
        """Run tailscale up."""
        try:
            subprocess.call(["tailscale", "up", f"--auth-key={auth_key}"])
        except subprocess.CalledProcessError as e:
            logger.error(f"error running `tailscale up` - {e}")
            raise e

    def down(self) -> None:
        """Run tailscale down."""
        try:
            subprocess.call(["tailscale", "down"])
        except subprocess.CalledProcessError as e:
            logger.error(f"error running `tailscale up` - {e}")
            raise e

    def funnel(self) -> None:
        """Run tailscale funnel."""
        try:
            subprocess.call(["tailscale", "funnel", "--bg", "8000"])
        except subprocess.CalledProcessError as e:
            logger.error(f"error running `tailscale up` - {e}")
            raise e

    @property
    def uri(self) -> str:
        """Return the tailscale uri."""
        tailscale_uri = ""
        p = subprocess.check_output(["tailscale", "funnel", "status", "--json"])
        ts_funnel_status = json.loads(p.decode())
        if ts_funnel_status:
            tailscale_host = next(iter(ts_funnel_status["Web"])).split(":")[0]
            tailscale_uri = f"https://{tailscale_host}"
        return tailscale_uri

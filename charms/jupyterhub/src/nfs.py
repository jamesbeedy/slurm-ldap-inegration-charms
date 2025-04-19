# Copyright 2025 Vantage Compute Corp
# See LICENSE file for licensing details.

"""NFSKernelServer."""

import logging
import subprocess
from pathlib import Path

from shutil import rmtree

from exceptions import NFSOpsError
import charms.operator_libs_linux.v0.apt as apt

logger = logging.getLogger()


class NFSKernelServer:
    """Facilitate nfs-server package lifecycle ops."""

    _package_name: str = "nfs-kernel-server"

    def install(self) -> None:
        """Install the nfs-kernel-server package using lib apt."""
        try:
            # Run `apt-get update`
            apt.update()
            apt.add_package(self._package_name)
        except apt.PackageNotFoundError as e:
            logger.error(
                f"{self._package_name} not found in package cache or on system"
            )
            raise NFSOpsError(e)
        except apt.PackageError as e:
            logger.error(
                f"Could not install {self._package_name}. Reason: %s", e.message
            )
            raise NFSOpsError(e)

        Path("/jupyterhub-nfs/working").mkdir(mode=0o777, parents=True, exist_ok=True)
        Path("/jupyterhub-nfs/etc").mkdir(mode=0o600, parents=True, exist_ok=True)

        etc_exports = Path("/etc/exports")
        if etc_exports.exists():
            etc_exports.unlink()
        etc_exports.write_text(
            "/jupyterhub-nfs    *(rw,sync,no_subtree_check,no_root_squash)"
        )

        subprocess.check_call(["exportfs", "-a"], shell=True)
        subprocess.check_call(["systemctl", "restart", "nfs-kernel-server"])

    def uninstall(self) -> None:
        """Uninstall the nfs-kernel-server package using libapt."""
        if apt.remove_package(self._package_name):
            logger.info(f"{self._package_name} removed from system.")
        else:
            logger.error(f"{self._package_name} not found on system")

        etc_exports = Path("/etc/exports")
        if etc_exports.exists():
            etc_exports.unlink()

        rmtree("/jupyterhub-nfs")

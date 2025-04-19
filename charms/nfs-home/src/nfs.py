# Copyright 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""NFSKernelServer."""

import logging
import subprocess
from pathlib import Path

import charms.operator_libs_linux.v0.apt as apt

logger = logging.getLogger()


class NFSOpsError(Exception):
    """Exception raised by NFSKernelServer."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]


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

        etc_exports = Path("/etc/exports")
        if etc_exports.exists():
            etc_exports.unlink()
        etc_exports.write_text("/home    *(rw,sync,no_subtree_check,root_squash)")

        subprocess.check_call(["exportfs", "-a"], shell=True)
        subprocess.check_call(["systemctl", "restart", "nfs-kernel-server"])
        subprocess.check_call(["pam-auth-update", "--enable", "mkhomedir"])

    def uninstall(self) -> None:
        """Uninstall the nfs-kernel-server package using libapt."""
        if apt.remove_package(self._package_name):
            logger.info(f"{self._package_name} removed from system.")
        else:
            logger.error(f"{self._package_name} not found on system")

        etc_exports = Path("/etc/exports")
        if etc_exports.exists():
            etc_exports.unlink()

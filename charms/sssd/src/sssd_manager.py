# Copyright 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""SSSDOps."""

import fileinput
import logging
import re
import subprocess
import sys
from pathlib import Path
from string import Template

import charms.operator_libs_linux.v0.apt as apt

logger = logging.getLogger()


class SSSDOpsError(Exception):
    """Exception raised by SSSDOps."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]


def _authorized_keys_command_user():
    pattern = re.compile(r"^[#]*AuthorizedKeysCommandUser ")

    for line in fileinput.input("/etc/ssh/sshd_config", inplace=True):
        if pattern.match(line):
            # replace the entire line
            sys.stdout.write("AuthorizedKeysCommandUser root\n")
        else:
            sys.stdout.write(line)


def _authorized_keys_command():
    pattern = re.compile(r"^[#]*AuthorizedKeysCommand ")

    for line in fileinput.input("/etc/ssh/sshd_config", inplace=True):
        if pattern.match(line):
            # replace the entire line
            sys.stdout.write("AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys\n")
        else:
            sys.stdout.write(line)


def _restart(service: str) -> None:
    """Restart sssd."""
    try:
        subprocess.call(["systemctl", "restart", service])
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise SSSDOpsError(e)


def _setup_lhome() -> None:
    """Arrange the local home dir to /lhome."""
    subprocess.call(["mkdir", "-p", "/lhome"])
    subprocess.call(["usermod", "ubuntu", "-m", "-d", "/lhome/ubuntu"])

    subprocess.call(
        r"sed -i 's+\(^HOME\|^# HOME\)=/home$+HOME=/lhome+g' /etc/default/useradd",
        shell=True,
    )
    subprocess.call(
        r"sed -i 's+\(^DHOME\|^# DHOME\)=/home$+DHOME=/lhome+g' /etc/adduser.conf",
        shell=True,
    )
    Path("/etc/apparmor.d/tunables/home.d/site.local").write_text("@{HOMEDIRS}+=/lhome")
    subprocess.call(["usermod", "-p", "'*'", "ubuntu"])
    subprocess.call(["snap", "set", "system", "homedirs=/lhome"])


class SSSDOps:
    """Facilitate sssd lifecycle ops."""

    def __init__(self, enable_autofs: bool):
        self._enable_autofs = enable_autofs

        self._packages = ["sssd", "sssd-ldap"]

        if enable_autofs:
            self._packages.extend(["autofs", "autofs-ldap"])

    def install(self) -> None:
        """Install packages and setup filesysytem."""
        try:
            apt.update()
            apt.add_package(self._packages)
        except apt.PackageNotFoundError as e:
            logger.error("package not found in package cache or on system")
            raise SSSDOpsError(e)
        except apt.PackageError as e:
            msg = f"Could not install packages. Reason: {e.message}"
            logger.error(msg)
            raise SSSDOpsError(msg)

        if self._enable_autofs:
            _setup_lhome()

        _authorized_keys_command_user()
        _authorized_keys_command()
        _restart("ssh")

        nsswitch_conf_template_path = Path("./templates/nsswitch.conf")
        nsswitch_conf = Path("/etc/nsswitch.conf")
        nsswitch_conf.write_text(nsswitch_conf_template_path.read_text())

    def render_config_and_restart(
        self,
        olc_suffix: str,
        domain: str,
        ldap_ip: str,
        sssd_binder_password: str,
    ) -> None:
        """Render the ssd.conf template and restart the service."""
        sssd_conf_template_path = Path(
            "./templates/sssd-autofs.conf" if self._enable_autofs else "./templates/sssd.conf"
        )
        sssd_conf_template = Template(sssd_conf_template_path.read_text())
        sssd_conf_content = sssd_conf_template.substitute(
            olc_suffix=olc_suffix,
            domain=domain,
            ldap_ip=ldap_ip,
            sssd_binder_password=sssd_binder_password,
        )
        sssd_conf = Path("/etc/sssd/sssd.conf")
        sssd_conf.write_text(sssd_conf_content)
        sssd_conf.chmod(0o600)
        _restart("sssd")
        if self._enable_autofs:
            _restart("autofs")

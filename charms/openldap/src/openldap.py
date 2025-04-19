# Copyright 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""OpenLDAPOps."""

import logging
import re
import socket
import subprocess
import tempfile
from pathlib import Path
from shutil import copy2
from textwrap import dedent
from typing import Literal

from exceptions import OpenLDAPOpsError

import charms.operator_libs_linux.v0.apt as apt

logger = logging.getLogger()


# _CERT_DIR = Path("/etc/ssl/ldap")
# _CERT_FILE = _CERT_DIR / "ldap.crt"
# _KEY_FILE = _CERT_DIR / "ldap.key"
# _CA_FILE = Path("/etc/ssl/certs/ca-certificates.crt")


def _create_certs(ip_address: str, organization_name: str) -> None:
    """Create certs for ldap."""
    try:
        subprocess.run(
            [
                "certtool",
                "--generate-privkey",
                "--bits=4096",
                "--outfile=/etc/ssl/private/mycakey.pem",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    ca_info = dedent(
        f"""
        cn = {organization_name}
        ca
        cert_signing_key
        expiration_days = 3650
        """
    )

    with tempfile.NamedTemporaryFile(delete_on_close=True) as fp:
        ca_info_path = Path(fp.name)
        ca_info_path.write_text(ca_info)

        try:
            subprocess.run(
                [
                    "certtool",
                    "--generate-self-signed",
                    "--load-privkey=/etc/ssl/private/mycakey.pem",
                    f"--template={ca_info_path}",
                    "--outfile=/usr/local/share/ca-certificates/mycacert.crt",
                ],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

    try:
        subprocess.run(
            ["update-ca-certificates"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    try:
        subprocess.run(
            [
                "certtool",
                "--generate-privkey",
                "--bits=2048",
                "--outfile=/etc/ldap/ldap01_slapd_key.pem",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    server_cert_info = dedent(
        f"""
        organization = {organization_name}
        cn = "{socket.getfqdn()}"
        dns_name = "{socket.getfqdn()}"
        ip_address = "{ip_address}"
        expiration_days = 365
        tls_www_server
        encryption_key
        signing_key
        """
    )

    with tempfile.NamedTemporaryFile(delete_on_close=True) as fp:
        cert_info_path = Path(fp.name)
        cert_info_path.write_text(server_cert_info)

        try:
            subprocess.run(
                [
                    "certtool",
                    "--generate-certificate",
                    "--load-privkey=/etc/ldap/ldap01_slapd_key.pem",
                    "--load-ca-certificate=/etc/ssl/certs/mycacert.pem",
                    "--load-ca-privkey=/etc/ssl/private/mycakey.pem",
                    f"--template={cert_info_path}",
                    "--outfile=/etc/ldap/ldap01_slapd_cert.pem",
                ],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

    try:
        subprocess.run(
            ["chgrp", "openldap", "/etc/ldap/ldap01_slapd_key.pem"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    try:
        subprocess.run(["chmod", "0640", "/etc/ldap/ldap01_slapd_key.pem"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)


def _get_ldap_database_index(olc_suffix: str) -> str:
    """Query the cn=config database to find the internal index N for the MDB.

    Returns:
        The string index N such that the DN is "olcDatabase={N}mdb,cn=config".

    Raises:
        RuntimeError: if the ldapsearch command fails or no matching DN is found.
    """
    cmd = [
        "ldapsearch",
        "-Y",
        "EXTERNAL",
        "-H",
        "ldapi:///",
        "-b",
        "cn=config",
        "-LLL",
        f"(olcSuffix={olc_suffix})",
        "dn",
    ]

    try:
        output = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"ldapsearch failed: {e}") from e

    for line in output.splitlines():
        match = re.match(r"^dn:\s*olcDatabase=\{(\d+)\}mdb,cn=config", line)
        if match:
            return match.group(1)

    raise RuntimeError(f"No MDB database serving suffix {olc_suffix} found")


def _update_ldap_tls_config() -> None:
    """Add cert, key, and ca to ldap config."""
    tls_config_ldif = dedent(
        """
        # Entry # 1 Update Schema for TLS
        dn: cn=config
        changetype: modify
        replace: olcTLSCertificateFile
        olcTLSCertificateFile: /etc/ldap/ldap01_slapd_cert.pem
        -
        replace: olcTLSCertificateKeyFile
        olcTLSCertificateKeyFile: /etc/ldap/ldap01_slapd_key.pem
        -
        replace: olcTLSCACertificateFile
        olcTLSCACertificateFile: /etc/ssl/certs/mycacert.pem
        """
    )
    _ldap_ex("modify", tls_config_ldif)


def _add_sssd_binder_user(idx: str, olc_suffix: str, sssd_binder_password: str) -> None:
    """Generate the sssd-binder service account password hash and and create the service account."""
    sssd_binder_password_hash = _slappasswd(sssd_binder_password)

    add_ssd_binder_ldif = dedent(
        f"""
        dn: cn=sssd-binder,ou=ServiceAccounts,{olc_suffix}
        objectClass: simpleSecurityObject
        objectClass: organizationalRole
        cn: sssd-binder
        description: Read-only service account for SSSD binding
        userPassword: {sssd_binder_password_hash}
        """
    )
    logger.debug(add_ssd_binder_ldif)
    _ldap_ex("add", add_ssd_binder_ldif)


def _add_organizational_units(olc_suffix: str) -> None:
    """Add organizational units to openldap."""
    add_organizational_units_ldif = dedent(
        f"""
        # Entry #1 ServiceAccounts
        dn: ou=ServiceAccounts,{olc_suffix}
        objectClass: organizationalUnit
        ou: ServiceAccounts

        # Entry #2 Groups
        dn: ou=Groups,{olc_suffix}
        objectclass: organizationalUnit
        ou: Groups

        # Entry #3 People
        dn: ou=People,{olc_suffix}
        objectclass: organizationalUnit
        ou: People
        """
    )
    logger.debug(add_organizational_units_ldif)
    _ldap_ex("add", add_organizational_units_ldif)


def _add_referential_integrity_module() -> None:
    """Add the referential integrity module.

    Note: For testing.

    # ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=module{0},cn=config olcModuleLoad
    SASL/EXTERNAL authentication started
    SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
    SASL SSF: 0
    # extended LDIF
    #
    # LDAPv3
    # base <cn=module{0},cn=config> with scope subtree
    # filter: (objectclass=*)
    # requesting: olcModuleLoad
    #

    # module{0}, config
    dn: cn=module{0},cn=config
    olcModuleLoad: {0}back_mdb
    olcModuleLoad: {1}refint
    olcModuleLoad: {2}memberof

    # search result
    search: 2
    result: 0 Success

    # numResponses: 2
    # numEntries: 1

    """
    add_refint_ldif = dedent(
        """
        dn: cn=module{0},cn=config
        changetype: modify
        add: olcModuleLoad
        olcModuleLoad: refint
        """
    )
    logger.debug(add_refint_ldif)
    _ldap_ex("modify", add_refint_ldif)


def _add_memberof_module_and_overlay(idx: str) -> None:
    """Add the memberof module and overlay.

    Note: For testing.

    # ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=module{0},cn=config olcModuleLoad
    SASL/EXTERNAL authentication started
    SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
    SASL SSF: 0
    # extended LDIF
    #
    # LDAPv3
    # base <cn=module{0},cn=config> with scope subtree
    # filter: (objectclass=*)
    # requesting: olcModuleLoad
    #

    # module{0}, config
    dn: cn=module{0},cn=config
    olcModuleLoad: {0}back_mdb
    olcModuleLoad: {1}refint
    olcModuleLoad: {2}memberof

    # search result
    search: 2
    result: 0 Success

    # numResponses: 2
    # numEntries: 1
    """
    add_memberof_ldif = dedent(
        """
        dn: cn=module{0},cn=config
        changetype: modify
        add: olcModuleLoad
        olcModuleLoad: memberof
        """
    )
    logger.debug(add_memberof_ldif)
    _ldap_ex("modify", add_memberof_ldif)

    add_memberof_overlay = dedent(
        f"""
        dn: olcOverlay=memberof,olcDatabase={{{idx}}}mdb,cn=config
        objectClass: olcMemberOf
        objectClass: olcOverlayConfig
        objectClass: olcConfig
        objectClass: top
        olcOverlay: memberof
        olcMemberOfRefInt: TRUE
        olcMemberOfDangling: ignore
        olcMemberOfGroupOC: groupOfNames
        olcMemberOfMemberAD: member
        olcMemberOfMemberOfAD: memberOf
        """
    )
    logger.debug(add_memberof_overlay)
    _ldap_ex("add", add_memberof_overlay)


def _add_automount_home_map_entries(olc_suffix: str, homedir_server_ipaddr: str) -> None:
    """Add automap home entries."""
    automount_mappings_ldif = dedent(
        f"""
        # ─── 1) Create the auto.master container ───────────────────────────────────
        dn: ou=auto.master,{olc_suffix}
        objectClass: top
        objectClass: organizationalUnit
        ou: auto.master

        # ─── 2) Master map “auto.master” ──────────────────────────────────────────
        dn: automountMapName=auto.master,ou=auto.master,{olc_suffix}
        objectClass: top
        objectClass: automountMap
        automountMapName: auto.master
        description: AutoFS master map

        # ─── 3) Entry in the master map for /home ➞ “auto.home” ───────────────────
        dn: automountKey=/home,automountMapName=auto.master,ou=auto.master,{olc_suffix}
        objectClass: top
        objectClass: automount
        automountKey: /home
        automountInformation: auto.home

        # ─── 4) The “auto.home” sub‑map itself ────────────────────────────────────
        dn: automountMapName=auto.home,ou=auto.master,{olc_suffix}
        objectClass: top
        objectClass: automountMap
        automountMapName: auto.home
        description: Home‑directory sub‑map

        # ─── 5) Wildcard entry for all users under auto.home ─────────────────────
        dn: automountKey=*,automountMapName=auto.home,ou=auto.master,{olc_suffix}
        objectClass: top
        objectClass: automount
        automountKey: *
        automountInformation: {homedir_server_ipaddr}:/home/&
        """
    )
    logger.debug(automount_mappings_ldif)
    _ldap_ex("add", automount_mappings_ldif)


def _add_additional_schemas() -> None:
    """Add schemas to openldap."""
    schemas = [
        # Path("./templates/autofs-schema.ldif"),
        Path("./templates/openssh-lpk-schema.ldif"),
    ]
    for schema_ldif in schemas:
        _ldap_ex("add", schema_ldif.read_text())


def _update_permissions(idx: str, olc_suffix: str) -> None:
    """Remove add write for EXTERNAL SASL."""
    update_acls = dedent(
        f"""
        dn: olcDatabase={{{idx}}}mdb,cn=config
        changetype: modify
        replace: olcAccess
        olcAccess: to attrs=userPassword     by self write by anonymous auth by * none
        olcAccess: to attrs=shadowLastChange by self write by * read
        olcAccess: to *                      by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
                                             by dn.exact="cn=admin,{olc_suffix}" manage
                                             by dn.exact="cn=sssd-binder,ou=ServiceAccounts,{olc_suffix}" read
                                             by * by users read
        """
    )

    logger.debug(update_acls)
    _ldap_ex("modify", update_acls)


def _ldap_ex(cmd: Literal["add", "modify"], ldif: str) -> None:
    """Add or modify an ldap mapping."""
    try:
        result = subprocess.run(
            [f"ldap{cmd}", "-Y", "EXTERNAL", "-H", "ldapi:///"],
            input=ldif,
            text=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    if result.returncode != 0:
        logger.error(f"ldap{cmd} failed: {result.stdout} / {result.stderr}")
        raise OpenLDAPOpsError(result.stderr)


def _ldap(cmd: Literal["add", "modify"], olc_suffix: str, admin_password: str, ldif: str) -> None:
    """Add or modify an ldap mapping."""
    try:
        process = subprocess.Popen(
            [
                f"ldap{cmd}",
                "-x",
                "-D",
                f"cn=admin,{olc_suffix}",
                "-v",
                "-w",
                admin_password,
            ],
            stdin=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(ldif)
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

        if process.returncode != 0:
            raise OpenLDAPOpsError(f"ldap{cmd} failed:\n{stderr}")


def _get_ldapsearch_result(base_dn: str) -> bool:
    """Execute an ldapsearch command and returns the 'result' code from the output.

    Args:
        base_dn (str): The base distinguished name (DN) to search.

    Returns:
        bool: True or False depending on if the entity exists.
    """
    try:
        # Build the command
        command = ["ldapsearch", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", base_dn]
        # Execute the command using Popen
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        output, error = process.communicate()

        # Search for the 'result' line
        match = re.search(r"result:\s*(\d+)", output)
        if match:
            return True if int(match.group(1)) == 0 else False
        else:
            if process.returncode != 0:
                raise RuntimeError(
                    f"ldapsearch command failed with code {process.returncode}: {error.strip()}"
                )
            raise ValueError("Result code not found in ldapsearch output.")

    except Exception as e:
        raise RuntimeError(f"An error occurred: {e}")


def _replace_nis_schema_with_rfc2307bis() -> None:
    """Replace nis schema with rfc2307bis.

    Replaces:
        include: file:///etc/ldap/schema/nis.ldif
    with:
        include: file:///etc/ldap/schema/gosa/rfc2307bis.ldif
    """
    slapd_init_ldif = Path("/usr/share/slapd/slapd.init.ldif")

    pattern = re.compile(r"^include:\s*file:///etc/ldap/schema/nis\.ldif\s*$")
    replacement = "include: file:///etc/ldap/schema/gosa/rfc2307bis.ldif\n"

    updated_lines = []
    for line in slapd_init_ldif.read_text().splitlines(keepends=True):
        if pattern.match(line):
            updated_lines.append(replacement)
        else:
            updated_lines.append(line)

    slapd_init_ldif.write_text("".join(updated_lines))


def _systemctl_slapd(command: str) -> None:
    """Restart slapd."""
    try:
        subprocess.call(["systemctl", command, "slapd"])
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)


def _set_debconf_value(package, question, val_type, value) -> None:
    """Set debconf value."""
    debconf_line = f"{package} {question} {val_type} {value}\n"
    try:
        process = subprocess.Popen(
            ["debconf-set-selections"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,  # Ensures strings, not bytes
        )
        stdout, stderr = process.communicate(debconf_line)
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    if process.returncode != 0:
        raise OpenLDAPOpsError(f"Failed to set debconf: {stderr.strip()}")


def _slappasswd(plaintext_password: str) -> None:
    """Execute slappasswd and return a hash."""
    try:
        p = subprocess.Popen(
            ["slappasswd", "-h", "{CRYPT}", "-s", plaintext_password],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = p.communicate()
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    return stdout.strip()


def _non_interactive_config_for_slapd(admin_password, domain, organization_name) -> None:
    slapd_non_interactive_configs = [
        ("slapd", "slapd/internal/adminpw", "password", admin_password),
        ("slapd", "slapd/internal/generated_adminpw", "password", admin_password),
        ("slapd", "slapd/password1", "password", admin_password),
        ("slapd", "slapd/password2", "password", admin_password),
        ("slapd", "slapd/domain", "string", domain),
        ("slapd", "shared/organization", "string", organization_name),
        ("slapd", "slapd/backend", "select", "MDB"),
        ("slapd", "slapd/no_configuration", "boolean", "false"),
        ("slapd", "slapd/purge_database", "boolean", "true"),
        ("slapd", "slapd/move_old_database", "boolean", "true"),
        ("slapd", "slapd/allow_ldap_v2", "boolean", "false"),
    ]

    for pkg, question, val_type, value in slapd_non_interactive_configs:
        _set_debconf_value(pkg, question, val_type, value)


class OpenLDAPOps:
    """Facilitate openldap lifecycle ops."""

    def __init__(self):
        self._packages = [
            "ldap-utils",
            "slapd",
            "debconf-utils",
            "gosa-schema",
            "gnutls-bin",
            "ssl-cert",
        ]

    def install(
        self,
        olc_suffix: str,
        domain: str,
        organization_name: str,
        admin_password: str,
        sssd_binder_password: str,
        ip_address: str,
    ) -> None:
        """Install packages."""
        _non_interactive_config_for_slapd(admin_password, domain, organization_name)

        try:
            apt.update()
            apt.add_package(self._packages)
        except apt.PackageNotFoundError as e:
            logger.error("package not found in package cache or on system")
            raise OpenLDAPOpsError(e)
        except apt.PackageError as e:
            msg = f"Could not install packages. Reason: {e.message}"
            logger.error(msg)
            raise OpenLDAPOpsError(msg)

        # Reinitialize slapd and use rfc2307bis schema.
        _systemctl_slapd("stop")
        try:
            subprocess.call(["rm", "-r", "/etc/ldap/slapd.d/*"])
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

        _replace_nis_schema_with_rfc2307bis()
        _non_interactive_config_for_slapd(admin_password, domain, organization_name)

        try:
            subprocess.call(
                ["/usr/sbin/dpkg-reconfigure", "slapd"],
                env={"DEBIAN_FRONTEND": "noninteractive"},
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

        # Put the slapd config in place.
        copy2("./templates/slapd.default", "/etc/default/slapd")

        # Create certs for ldap server and configure tls.
        # _create_certs(domain, organization_name)
        _create_certs(ip_address, organization_name)
        _update_ldap_tls_config()
        _systemctl_slapd("restart")

        idx = ""
        try:
            idx = _get_ldap_database_index(olc_suffix)
        except RuntimeError as err:
            logger.error(err)
            raise (err)

        logger.debug(f"Database index for suffix '{olc_suffix}': {idx}")

        # Add extra schemas.
        _add_additional_schemas()

        # Give EXTERNAL SASL write permissions
        _update_permissions(idx, olc_suffix)

        # Add referential integrity and memberof modules.
        _add_referential_integrity_module()
        _add_memberof_module_and_overlay(idx)

        # Add organizational units.
        _add_organizational_units(olc_suffix)

        # Add sssd-binder user and assign permissions.
        _add_sssd_binder_user(idx, olc_suffix, sssd_binder_password)

    def add_user(
        self,
        username: str,
        password: str,
        email: str,
        uid: str,
        ssh_key: str,
        olc_suffix: str,
    ) -> None:
        """Add a user to the system."""
        pw = _slappasswd(password)

        user_details_ldif = dedent(
            f"""
            # Entry 1: uid={username},ou=People,{olc_suffix}
            dn: uid={username},ou=People,{olc_suffix}
            cn: {username}
            gidnumber: 5599
            homedirectory: /home/{username}
            loginshell: /bin/bash
            mail: {email}
            objectclass: top
            objectclass: inetOrgPerson
            objectclass: posixAccount
            objectclass: ldapPublicKey
            sshpublickey: {ssh_key}
            uid: {username}
            uidnumber: {uid}
            sn: {username}
            userpassword: {pw}
            """
        )
        logger.debug(user_details_ldif)
        _ldap_ex("add", user_details_ldif)

        ldif = ""
        if _get_ldapsearch_result(f"cn=slurm-users,ou=Groups,{olc_suffix}") is not True:
            ldif = dedent(
                f"""
                dn: cn=slurm-users,ou=Groups,{olc_suffix}
                objectClass: top
                objectClass: groupOfNames
                objectClass: posixGroup
                cn: slurm-users
                description: Slurm User Group
                member: uid={username},ou=People,{olc_suffix}
                gidNumber: 5599
                """
            )
            logger.debug(ldif)
            _ldap_ex("add", ldif)

        else:
            ldif = dedent(
                f"""
                dn: cn=slurm-users,ou=Groups,{olc_suffix}
                changetype: modify
                add: memberUid
                memberUid: {username}
                """
            )
            logger.debug(ldif)
            _ldap_ex("modify", ldif)

    def configure_automount_maps(self, olc_suffix: str, homedir_server_ipaddr: str) -> None:
        """Add automount home mappings."""
        _add_automount_home_map_entries(olc_suffix, homedir_server_ipaddr)

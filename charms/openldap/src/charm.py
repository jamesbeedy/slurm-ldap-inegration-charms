#!/usr/bin/env python3
# Copyright (c) 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""OpenLDAPOperatorCharm."""

import logging
import secrets

from exceptions import OpenLDAPOpsError
from openldap import OpenLDAPOps
from ops import (
    ActionEvent,
    ActiveStatus,
    BlockedStatus,
    CharmBase,
    InstallEvent,
    RelationJoinedEvent,
    StoredState,
    UpdateStatusEvent,
    WaitingStatus,
    main,
)

logger = logging.getLogger()


class IngressAddressUnavailableError(Exception):
    """Exception raised when the ingress address is unavailable."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]


class OpenLDAPOperatorCharm(CharmBase):
    """OpenLDAP Operator lifecycle events."""

    _stored = StoredState()

    def __init__(self, *args, **kwargs):
        """Init _stored attributes and interfaces, observe events."""
        super().__init__(*args, **kwargs)

        self._stored.set_default(
            domain=str(),
            organization_name=str(),
            ldap_install_complete=False,
        )

        # self.sssd = SSSD(self, "sssd")

        event_handler_bindings = {
            self.on.install: self._on_install,
            self.on.update_status: self._on_update_status,
            self.on["homedir-server-ipaddr"].relation_joined: self._on_homedir_server_joined,
            self.on["sssd"].relation_joined: self._on_sssd_relation_joined,
            # Actions
            self.on.add_user_action: self._on_add_user_action,
            self.on.get_admin_password_action: self._on_get_admin_password_action,
            self.on.get_sssd_binder_password_action: self._on_get_sssd_binder_password_action,
        }
        for event, handler in event_handler_bindings.items():
            self.framework.observe(event, handler)

    def _on_install(self, event: InstallEvent) -> None:
        """Perform installation operations."""
        admin_password = secrets.token_urlsafe(32)
        content = {"password": admin_password}
        secret = self.app.add_secret(content, label="admin-password")
        logger.debug(f"admin-password secret id: {secret.id}")

        sssd_binder_password = secrets.token_urlsafe(32)
        content = {"password": sssd_binder_password}
        secret = self.app.add_secret(content, label="sssd-binder-password")
        logger.debug(f"sssd-binder-password secret id: {secret.id}")

        self._domain = self.config.get("domain")
        self._organization_name = self.config.get("organization-name")

        try:
            self.unit.status = WaitingStatus("Installing OpenLDAP server...")
            OpenLDAPOps().install(
                olc_suffix=self._olc_suffix,
                domain=self._domain,
                organization_name=self._organization_name,
                admin_password=admin_password,
                sssd_binder_password=sssd_binder_password,
                ip_address=self._ingress_address,
            )
            self.unit.status = ActiveStatus("OpenLDAP installed.")
            self.unit.status = ActiveStatus(f"Serving: {self._olc_suffix}")
        except OpenLDAPOpsError as e:
            self.unit.status = BlockedStatus("Trouble installing OpenLDAP, please debug.")
            logger.debug(e)
            event.defer()
            return

        self.unit.open_port("tcp", 389)
        self._stored.ldap_install_complete = True

    def _on_sssd_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Send data to SSSD."""
        if self._stored.ldap_install_complete is not True:
            logger.debug("Waiting on ldap installation to complete....")
            event.defer()
            return

        secret = self.model.get_secret(label="sssd-binder-password")
        secret.grant(event.relation)

        event.relation.data[self.app]["sssd-binder-password-secret-id"] = secret.id
        event.relation.data[self.app]["domain"] = self._domain
        event.relation.data[self.app]["olc-suffix"] = self._olc_suffix

    def _on_homedir_server_joined(self, event: RelationJoinedEvent) -> None:
        """Get the homedir server ip address and configure the maps for automount."""
        if self._stored.ldap_install_complete is not True:
            logger.debug("Waiting on ldap installation to complete....")
            event.defer()
            return

        homedir_server_ipaddr = event.relation.data[event.unit]["ingress-address"]

        try:
            self.unit.status = WaitingStatus("Adding automount maps to ldap server...")
            OpenLDAPOps().configure_automount_maps(self._olc_suffix, homedir_server_ipaddr)
            self.unit.status = ActiveStatus("Automount maps successfully added.")
            self.unit.status = ActiveStatus("")
        except OpenLDAPOpsError as e:
            self.unit.status = BlockedStatus(
                "Trouble adding automount maps to ldap, please debug."
            )
            logger.debug(e)
            event.defer()
            return

    def _on_update_status(self, event: UpdateStatusEvent) -> None:
        """Set the status to the olx_suffix."""
        self.unit.status = ActiveStatus(f"Serving: {self._olc_suffix}")

    def _on_add_user_action(self, event: ActionEvent) -> None:
        """Add a user to ldap."""
        username = ""
        password = ""
        email = ""
        ssh_key = ""
        uid = ""

        result = "User not created created."

        if (un := event.params.get("username")) is not None:
            username = un
        if (pw := event.params.get("password")) is not None:
            password = pw
        if (em := event.params.get("email")) is not None:
            email = em
        if (sk := event.params.get("ssh-key")) is not None:
            ssh_key = sk
        if (u_id := event.params.get("uid")) is not None:
            uid = u_id
        if all([username, password, email, ssh_key, uid]):
            OpenLDAPOps().add_user(username, password, email, uid, ssh_key, self._olc_suffix)
            result = f"User created: {username}."

        event.set_results({"result": result})

    def _on_get_admin_password_action(self, event: ActionEvent) -> None:
        """Return the ldap admin password."""
        event.set_results({"password": self._admin_password})

    def _on_get_sssd_binder_password_action(self, event: ActionEvent) -> None:
        """Return the ldap admin password."""
        event.set_results({"password": self._sssd_binder_password})

    @property
    def _admin_password(self) -> str:
        """Return the ldap admin_password from stored state."""
        secret = self.model.get_secret(label="admin-password")
        return secret.get_content()["password"]

    @property
    def _sssd_binder_password(self) -> str:
        """Return the sssd-binder password from stored state."""
        secret = self.model.get_secret(label="sssd-binder-password")
        return secret.get_content()["password"]

    @property
    def _olc_suffix(self) -> str:
        """Return the olc_suffix from the domain."""
        return ",".join([f"dc={dc}" for dc in self._domain.split(".")])

    @property
    def _domain(self) -> str:
        """Return the ldap domain from stored state."""
        return self._stored.domain

    @_domain.setter
    def _domain(self, domain: str) -> None:
        """Set the domain in stored state."""
        self._stored.domain = domain

    @property
    def _organization_name(self) -> str:
        """Return the ldap organization name from stored state."""
        return self._stored.organization_name

    @_organization_name.setter
    def _organization_name(self, organization_name: str) -> None:
        """Set the organization name in stored state."""
        self._stored.organization_name = organization_name

    @property
    def _ingress_address(self) -> str:
        """Return the ingress_address from the peer relation if it exists."""
        if (peer_binding := self.model.get_binding("openldap-peer")) is not None:
            ingress_address = f"{peer_binding.network.ingress_address}"
            logger.debug(f"ingress_address: {ingress_address}")
            return ingress_address
        raise IngressAddressUnavailableError("Ingress address unavailable")


if __name__ == "__main__":  # pragma: nocover
    main(OpenLDAPOperatorCharm)

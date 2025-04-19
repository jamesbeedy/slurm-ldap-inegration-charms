#!/usr/bin/env python3
# Copyright (c) 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""SSSDOperatorCharm."""

import logging

from ops import (
    CharmBase,
    InstallEvent,
    RelationChangedEvent,
    StoredState,
    ActiveStatus,
    BlockedStatus,
    WaitingStatus,
    main,
)

from sssd_manager import SSSDOps, SSSDOpsError


logger = logging.getLogger()


class SSSDOperatorCharm(CharmBase):
    """SSSD Operator lifecycle events."""

    _stored = StoredState()

    def __init__(self, *args, **kwargs):
        """Init _stored attributes and interfaces, observe events."""
        super().__init__(*args, **kwargs)

        self._stored.set_default(sssd_installed=False)

        self._sssd = SSSDOps(self.config.get("enable-autofs"))

        event_handler_bindings = {
            self.on.install: self._on_install,
            self.on["ldap"].relation_changed: self._on_ldap_relation_changed,
        }
        for event, handler in event_handler_bindings.items():
            self.framework.observe(event, handler)

    def _on_install(self, event: InstallEvent) -> None:
        """Perform installation operations."""

        try:
            self.unit.status = WaitingStatus("Installing SSSD ...")
            self._sssd.install()
            self.unit.status = ActiveStatus("SSSD installed.")
            self.unit.status = ActiveStatus("")
            self._stored.sssd_installed = True
        except SSSDOpsError as e:
            self.unit.status = BlockedStatus("Trouble installing SSSD, please debug.")
            logger.debug(e)
            event.defer()
            return

    def _on_ldap_relation_changed(self, event: RelationChangedEvent) -> None:
        """Recieve relation data from ldap."""

        if self._stored.sssd_installed is not True:
            logger.debug("Waiting on sssd to complete install, eferring event.")
            event.defer()
            return

        unit_data = event.relation.data.get(event.unit, None)
        app_data = event.relation.data.get(event.app, None)

        if not (unit_data and app_data):
            logger.debug(f"UNIT DATA: {unit_data}")
            logger.debug(f"APP DATA: {app_data}")
            logger.debug("Dependencies unmet, deferring event.")
            event.defer()
            return

        secret_id = event.relation.data[event.app].get(
            "sssd-binder-password-secret-id", None
        )
        olc_suffix = event.relation.data[event.app].get("olc-suffix", None)
        domain = event.relation.data[event.app].get("domain", None)
        ldap_ip = event.relation.data[event.unit].get("ingress-address", None)

        if not all([secret_id, domain, olc_suffix, ldap_ip]):
            logger.debug(f"secret-id: {secret_id}")
            logger.debug(f"domain: {domain}")
            logger.debug(f"olc-suffix: {olc_suffix}")
            logger.debug(f"ingress-address: {ldap_ip}")
            logger.debug("Dependencies unmet, deferring event.")
            event.defer()
            return

        secret = self.model.get_secret(id=secret_id, label="sssd-binder-password")
        sssd_binder_password = secret.get_content().get("password", None)
        self._sssd.render_config_and_restart(
            olc_suffix, domain, ldap_ip, sssd_binder_password
        )


if __name__ == "__main__":  # pragma: nocover
    main(SSSDOperatorCharm)

#!/usr/bin/env python3
# Copyright (c) 2025 Vantage Compute Corp.
# See LICENSE file for licensing details.

"""JupyterhubOperatorCharm."""

import logging

from ops import (
    CharmBase,
    ActionEvent,
    InstallEvent,
    StartEvent,
    RemoveEvent,
    ConfigChangedEvent,
    ActiveStatus,
    BlockedStatus,
    WaitingStatus,
    StoredState,
    main,
)

from charms.filesystem_client.v0.filesystem_info import FilesystemProvides, NfsInfo

from exceptions import (
    NFSOpsError,
    JupyterhubOpsError,
    TailscaleError,
    IngressAddressUnavailableError,
)
from nfs import NFSKernelServer
from jupyterhub import JupyterhubOps
from tailscale import Tailscale

logger = logging.getLogger()


class JupyterhubOperatorCharm(CharmBase):
    """Jupyterhub Operator lifecycle events."""

    _stored = StoredState()

    def __init__(self, *args, **kwargs):
        """Init _stored attributes and interfaces, observe events."""
        super().__init__(*args, **kwargs)

        self._stored.set_default(tailscale_auth_key="")

        self._filesystem = FilesystemProvides(self, "filesystem", "jupyterhub-peer")

        event_handler_bindings = {
            self.on.install: self._on_install,
            self.on.start: self._on_start,
            self.on.config_changed: self._on_config_changed,
            self.on.remove: self._on_uninstall,
            self.on.get_jupyterhub_url_action: self._on_get_jupyterhub_url_action,
        }
        for event, handler in event_handler_bindings.items():
            self.framework.observe(event, handler)

    def _on_install(self, event: InstallEvent) -> None:
        """Perform installation operations."""
        try:
            self.unit.status = WaitingStatus("Installing NFS server...")
            NFSKernelServer().install()
            self.unit.status = ActiveStatus("NFS server installed.")
            self.unit.status = ActiveStatus("")
        except NFSOpsError as e:
            self.unit.status = BlockedStatus(
                "Trouble installing NFS server, please debug."
            )
            logger.debug(e)
            event.defer()
            return

        try:
            self.unit.status = WaitingStatus("Installing jupyterhub server...")
            JupyterhubOps().install()
            JupyterhubOps().configure(ingress_address=self._ingress_address)
            self.unit.status = ActiveStatus("jupyterhub server installed.")
            self.unit.status = ActiveStatus("")
        except JupyterhubOpsError as e:
            self.unit.status = BlockedStatus(
                "Trouble installing jupyterhub server, please debug."
            )
            logger.debug(e)
            event.defer()
            return

        try:
            self.unit.status = WaitingStatus("Installing tailscale...")
            Tailscale().install()
            self.unit.status = ActiveStatus("tailscale installed.")
            self.unit.status = ActiveStatus("")
        except TailscaleError as e:
            self.unit.status = BlockedStatus(
                "Trouble installing tailscale, please debug."
            )
            logger.debug(e)
            event.defer()
            return


    def _on_start(self, event: StartEvent) -> None:
        """Start hook."""
        self._filesystem.set_info(
            NfsInfo(
                hostname=self._ingress_address,
                path="/jupyterhub-nfs",
                port=None,
            )
        )

        JupyterhubOps().start()

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Perform config-changed operations."""
        if (
            charm_config_tailscale_auth_key := self.config.get(
                "tailscale-auth-key-secret-id"
            )
        ) != "":
            if charm_config_tailscale_auth_key != self._stored.tailscale_auth_key:
                logger.debug("## Configuring tailscale and jupyterhub.")
                self._stored.tailscale_auth_key = charm_config_tailscale_auth_key

                tailscale = Tailscale()
                tailscale.down()
                tailscale.up(
                    self.model.get_secret(
                        id=charm_config_tailscale_auth_key
                    ).get_content()["tailscale-auth-key"]
                )
                tailscale.funnel()

                JupyterhubOps().configure(
                    ingress_address=self._ingress_address,
                    oidc_client_secret=self.config.get("oidc-client-secret"),
                    keycloak_url=self.config.get("keycloak-url"),
                    tailscale_uri=tailscale.uri,
                )
                JupyterhubOps().restart()
            else:
                logger.debug("Nothing to configure.....")
        else:
            JupyterhubOps().configure(
                ingress_address=self._ingress_address,
                oidc_client_secret=self.config.get("oidc-client-secret"),
                keycloak_url=self.config.get("keycloak-url"),
                tailscale_uri=None,
            )
            self.unit.open_port("tcp", 8000) 
            JupyterhubOps().restart()
        self.unit.status = ActiveStatus(self._jupyterhub_url)

    def _on_uninstall(self, event: RemoveEvent) -> None:
        """Perform uninstallation operations for nfs server and jupyterhub."""
        try:
            self.unit.status = WaitingStatus("Uninstalling ....")
            JupyterhubOps().uninstall()
            Tailscale().uninstall()
            NFSKernelServer().uninstall()
        except Exception:
            self.unit.status = BlockedStatus("Trouble uninstalling, please debug.")

    @property
    def _ingress_address(self) -> str:
        """Return the ingress_address from the peer relation if it exists."""
        if (peer_binding := self.model.get_binding("jupyterhub-peer")) is not None:
            ingress_address = f"{peer_binding.network.ingress_address}"
            logger.debug(f"ingress_address: {ingress_address}")
            return ingress_address
        raise IngressAddressUnavailableError("Ingress address unavailable")

    def _on_get_jupyterhub_url_action(self, event: ActionEvent) -> None:
        """Return jupyterhub url."""
        event.set_results({"url": self._jupyterhub_url})

    @property
    def _jupyterhub_url(self) -> str:
        jupyterhub_url = ""
        if self.config.get("tailscale-auth-key-secret-id") != "":
            jupyterhub_url = Tailscale().uri
        else:
            jupyterhub_url = f"http://{self._ingress_address}:8000"
        return jupyterhub_url


if __name__ == "__main__":  # pragma: nocover
    main(JupyterhubOperatorCharm)

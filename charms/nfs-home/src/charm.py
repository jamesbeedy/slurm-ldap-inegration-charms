#!/usr/bin/env python3
# Copyright (c) 2025 Vantage Compute Corp.
# See LICENSE file for licensing details.

"""NFSHomeOperatorCharm."""

import logging

from nfs import NFSKernelServer, NFSOpsError
from ops import (
    ActiveStatus,
    BlockedStatus,
    CharmBase,
    InstallEvent,
    RemoveEvent,
    WaitingStatus,
    main,
)

logger = logging.getLogger()


class NFSHomeOperatorCharm(CharmBase):
    """NFSHome Operator lifecycle events."""

    def __init__(self, *args, **kwargs):
        """Init _stored attributes and interfaces, observe events."""
        super().__init__(*args, **kwargs)

        event_handler_bindings = {
            self.on.install: self._on_install,
            self.on.remove: self._on_uninstall,
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
            self.unit.status = BlockedStatus("Trouble installing NFS server, please debug.")
            logger.debug(e)
            event.defer()
            return

    def _on_uninstall(self, event: RemoveEvent) -> None:
        """Perform uninstallation operations for nfs-kernel-server."""
        try:
            self.unit.status = WaitingStatus("Uninstalling....")
            NFSKernelServer().uninstall()
        except Exception:
            self.unit.status = BlockedStatus("Trouble uninstalling, please debug.")


if __name__ == "__main__":  # pragma: nocover
    main(NFSHomeOperatorCharm)

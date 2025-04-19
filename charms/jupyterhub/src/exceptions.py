# Copyright (c) 2025 Vantage Compute Corp.
# See LICENSE file for licensing details.
"""Exceptions.py"""


class IngressAddressUnavailableError(Exception):
    """Exception raised when the ingress address is unavailable."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]


class TailscaleError(Exception):
    """Exception raised by tailscale installer."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]


class JupyterhubOpsError(Exception):
    """Exception raised by jupyterhub installer."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]


class NFSOpsError(Exception):
    """Exception raised by nfs installer."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]

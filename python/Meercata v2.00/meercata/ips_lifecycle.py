"""Transaction orchestration for the gated nftables IPS policy foundation."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from meercata.ips_config import IpsConfig
from meercata.models import TransactionRecord
from meercata.nftables_policy import NftablesPolicy
from meercata.transaction import TransactionActions, TransactionEngine


class NftablesActivator(Protocol):
    def snapshot(self, record: TransactionRecord) -> Mapping[str, Any]: ...
    def apply(self, record: TransactionRecord) -> Mapping[str, Any]: ...
    def verify(self, record: TransactionRecord) -> Mapping[str, Any]: ...
    def rollback(self, record: TransactionRecord) -> Mapping[str, Any]: ...


class IpsNftablesWorkflow:
    """Run an owned policy transaction; public CLI activation remains gated."""

    def __init__(
        self,
        config: IpsConfig,
        engine: TransactionEngine,
        activator: NftablesActivator,
    ) -> None:
        config.validate()
        self.config = config
        self.engine = engine
        self.activator = activator

    def activate_policy(self) -> TransactionRecord:
        actions = TransactionActions(
            snapshot=lambda record: self.activator.snapshot(record),
            stage=lambda record: self._stage(record),
            validate=lambda record: self._validate(record),
            apply=lambda record: self.activator.apply(record),
            verify=lambda record: self.activator.verify(record),
            rollback=lambda record: self.activator.rollback(record),
        )
        return self.engine.execute(
            "ips.activate",
            actions,
            redacted_arguments=self.intent,
        )

    @property
    def intent(self) -> dict[str, Any]:
        return {
            "interface": self.config.interface,
            "queue": self.config.queue,
            "fail_policy": self.config.fail_policy,
            "traffic_scope": self.config.traffic_scope,
        }

    def _stage(self, record: TransactionRecord) -> Mapping[str, Any]:
        policy = NftablesPolicy.from_config(record.transaction_id, self.config)
        return {
            "intent": self.intent,
            "transaction_id": policy.transaction_id,
            "fail_open": policy.fail_open,
        }

    def _validate(self, record: TransactionRecord) -> Mapping[str, Any]:
        self.config.validate()
        policy = NftablesPolicy.from_config(record.transaction_id, self.config)
        return {
            "transaction_id": policy.transaction_id,
            "fail_open": policy.fail_open,
            "traffic_scope": self.config.traffic_scope,
        }

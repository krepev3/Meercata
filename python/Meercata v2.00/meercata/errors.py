"""Typed failures exposed by the control-plane foundation."""


class MeercataError(Exception):
    """Base class for expected Meercata failures."""


class InvalidModelError(MeercataError):
    """Persisted or caller-provided model data is invalid."""


class UnsafePathError(MeercataError):
    """A path falls outside its allowlisted boundary."""


class LockHeldError(MeercataError):
    """Another controller owns the mutation lock."""


class AuditError(MeercataError):
    """A required audit record could not be persisted."""


class StateStoreError(MeercataError):
    """Durable transaction state could not be read or written safely."""


class UnknownCommandError(MeercataError):
    """A command identifier is not in the runner allowlist."""


class InvalidCommandError(MeercataError):
    """An allowlisted command definition is unsafe or malformed."""


class TransactionFailed(MeercataError):
    """A transaction failed and was rolled back or needs recovery."""

    def __init__(
        self,
        transaction_id: str,
        cause: BaseException,
        rollback_error: BaseException | None = None,
    ) -> None:
        self.transaction_id = transaction_id
        self.cause = cause
        self.rollback_error = rollback_error
        message = f"transaction {transaction_id} failed: {type(cause).__name__}: {cause}"
        if rollback_error is not None:
            message += f"; rollback failed: {type(rollback_error).__name__}: {rollback_error}"
        super().__init__(message)


class HealthConfigurationError(MeercataError):
    """Health configuration is missing, unsafe, or invalid."""


class HealthCollectionError(MeercataError):
    """A health data source returned invalid or unusable data."""


class MonitorError(MeercataError):
    """Durable monitoring state or transition evidence is unsafe or unavailable."""


class MonitorDeliveryError(MeercataError):
    """Monitoring delivery configuration, outbox, or receipt state is unsafe."""


class RuleConfigurationError(MeercataError):
    """RuleOps configuration is missing, unsafe, or invalid."""


class IpsConfigurationError(MeercataError):
    """IPS configuration is missing, unsafe, or outside the approved scope."""


class NftablesPolicyError(MeercataError):
    """A Meercata nftables policy or observed table violates its contract."""


class RuleParseError(MeercataError):
    """A ruleset cannot be safely indexed for policy evaluation."""


class RuleStoreError(MeercataError):
    """A RuleOps candidate or manifest is missing, unsafe, or corrupt."""


class RuleOperationError(MeercataError):
    """A RuleOps command, validation, reload, or policy check failed."""


class PrivilegedOperationError(MeercataError):
    """A fixed privileged helper operation was denied or failed safely."""


class PackagingError(MeercataError):
    """A production package image is unsafe, incomplete, or inconsistent."""


class QualificationError(MeercataError):
    """A staged production image failed disposable-root qualification."""

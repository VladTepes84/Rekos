"""Domain errors surfaced by the REKOS CLI."""


class RekosError(Exception):
    """Base exception for expected REKOS failures."""


class CaseExistsError(RekosError):
    """Raised when creating a case that already exists."""


class CaseNotFoundError(RekosError):
    """Raised when a requested case does not exist."""


class InvalidCaseNameError(RekosError):
    """Raised when a case name cannot be mapped to a local case folder."""


class UnsupportedReportFormatError(RekosError):
    """Raised when a report format is not implemented."""


class ExternalToolMissingError(RekosError):
    """Raised when an optional passive OSINT tool is unavailable."""


class ExternalToolExecutionError(RekosError):
    """Raised when an optional passive OSINT tool fails."""


class ExternalToolTimeoutError(ExternalToolExecutionError):
    """Raised when an optional passive OSINT tool exceeds its timeout."""

"""Engine results and how they combine into the final verdict."""
from dataclasses import asdict, dataclass, field

# Engine verdicts. "error" fails closed (counts as suspicious); "skipped" is neutral.
RANK = {"clean": 0, "skipped": 0, "suspicious": 1, "error": 1, "blocked": 2, "malicious": 3}


@dataclass
class EngineResult:
    engine: str
    verdict: str
    detail: str = ""
    ms: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    sha256: str
    size: int
    mime: str
    verdict: str          # clean | suspicious | blocked | malicious
    reason: str
    results: list[dict] = field(default_factory=list)
    ms: int = 0
    cached: bool = False

    @property
    def flagged_engines(self) -> list[str]:
        return sorted({r["engine"] for r in self.results if RANK.get(r["verdict"], 0) > 0})


def combine(results: list[EngineResult]) -> tuple[str, str]:
    """Worst engine wins: malicious > blocked > suspicious (incl. errors) > clean."""
    worst = max(results, key=lambda r: RANK.get(r.verdict, 1), default=None)
    if worst is None or RANK.get(worst.verdict, 1) == 0:
        return "clean", ""
    verdict = "suspicious" if worst.verdict == "error" else worst.verdict
    return verdict, f"{worst.engine}: {worst.detail}"

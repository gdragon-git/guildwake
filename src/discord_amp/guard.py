"""Fail-closed reduction of two host-local observations. No API access."""
from .config import current
from dataclasses import dataclass, asdict
import hashlib
import math


@dataclass(frozen=True)
class Verdict:
    state: str = "unknown"
    reason: str = "observation_failed"
    covered: bool = False
    selected_active: bool = False
    age_ms: int | None = None
    generation: str = ""

    def public(self):
        return asdict(self)


def assess(first, second, now, boot):
    try:
        signatures = []
        other = selected = maintenance = False
        for snap in (first, second):
            if snap["boot"] != boot or snap["inventory_ok"] is not True or snap["errors"]:
                return Verdict()
            start, end = snap["start"], snap["end"]
            if not all(type(v) in {int, float} and math.isfinite(v) for v in (start, end, now)):
                return Verdict()
            if not (0 <= now - end <= 2 and 0 <= end - start <= .25):
                return Verdict(reason="stale_observation")
            rows = snap["rows"]
            if set(rows) != set(snap["relevant_pids"]):
                return Verdict(reason="coverage_mismatch")
            seen = set()
            signature = []
            for pid, row in rows.items():
                if type(pid) is not int or pid <= 0 or row["start_ticks"] <= 0:
                    return Verdict()
                roots = row["instances"]
                if len(roots) > 1 or set(roots) - set((current().instances)) or not row["stable"]:
                    return Verdict(reason="unclassified_process")
                task = row.get("maintenance", False)
                if type(task) is not bool:
                    return Verdict(reason="unclassified_process")
                if task:
                    if roots or row['container'] or row['management'] or row['application_activity'] is not True:
                        return Verdict(reason="unclassified_process")
                    maintenance = True
                elif row["management"] is not True:
                    if not roots or roots == (current().management,):
                        return Verdict(reason="unclassified_process")
                    other |= roots != ((current().selected),)
                    selected |= roots == ((current().selected),) and row["application_activity"]
                if row["container"]:
                    if roots != (row["container"],):
                        return Verdict()
                    seen.add(pid)
                signature.append((pid, row["start_ticks"], roots, row["fingerprint"], row["management"], row["application_activity"], task))
            if seen != set(snap["container_pids"]) or snap["unmapped_containers"]:
                return Verdict(reason="coverage_mismatch")
            signatures.append(sorted(signature))
        if first["end"] > second["start"] or signatures[0] != signatures[1] or first["inventory"] != second["inventory"]:
            return Verdict(reason="observation_changed")
        generation = hashlib.sha256(f"{boot}:{second['end']}".encode()).hexdigest()[:32]
        return Verdict("busy" if other or maintenance else "clear", "other_activity" if other else "amp_maintenance" if maintenance else "observed", True, bool(selected),
                       int((now - second['end']) * 1000), generation)
    except (KeyError, TypeError, ValueError, OverflowError):
        return Verdict()

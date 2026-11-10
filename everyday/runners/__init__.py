"""Runner registry. A runner group is a function(ctx) -> [(check_id, status, detail), ...] that provides one or more KB checks.
Add a new automated check by writing a function with @group("name", "CHECK-ID", ...) in any module in this folder."""
import importlib, pkgutil
GROUPS = []   # (name, tuple(ids), fn)

def group(name, *ids):
    def deco(fn): GROUPS.append((name, tuple(ids), fn)); return fn
    return deco

def load_all():
    if GROUPS: return GROUPS
    for m in pkgutil.iter_modules(__path__): importlib.import_module(f"{__name__}.{m.name}")
    return GROUPS

def provided_ids():
    return {i for _, ids, _ in load_all() for i in ids}

from typing import Any, Dict


def set_value(path: str, data: Dict[str, Any], params: Any, ctx: Any):
    if path == params.path:
        print("Setting %s to %s for %s" % (params.value, params.name, path))
        data[params.name] = params.value
    else:
        return None

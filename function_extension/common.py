from typing import Any, Dict


def set_value(path: str, data: Dict[str, Any], params: Any, ctx: Any):
    if path == params.path:
        keys = params.name.split("/")
        current = data
        for key in keys[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        current[keys[-1]] = params.value
    return data


def increase_value(path: str, data: Dict[str, Any], params: Any, ctx: Any):
    if path == params.path:
        data[params.name] += params.offset
        if data[params.name] > params.limit:
            data[params.name] = params.init_value
    return data


def decrease_value(path: str, data: Dict[str, Any], params: Any, ctx: Any):
    if path == params.path:
        data[params.name] -= params.offset
        if data[params.name] < params.limit:
            data[params.name] = params.init_value
    return data

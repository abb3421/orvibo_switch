
from .const import (
    DOMAIN,
    ORVIBO_SWITCH_MODEL
)

def get_data_from_list(data: list[dict], key1: str, value1, key2: str, def_value):
    try:
        for device in data:
            if device.get(key1) == value1:
                return device.get(key2, def_value)
        return def_value
    except Exception as e:
        print(f"ERROR: {e}")
        return None

def set_data_in_list(data: list[dict], key1: str, value1, key2: str, def_value)->bool:
    for device in data:
        if device.get(key1) == value1:
            device[key2] = def_value
            return True
    return False

def deduplicate_by_key(data: list[dict], key: str):
    seen = set()
    result = []
    for item in data:
        device_id = item.get(key)
        if device_id is not None and device_id not in seen:
            seen.add(device_id)
            result.append(item)
    return result

def get_current_floors(hass):
    return hass.data[DOMAIN]["floor"]

def get_current_family(hass):
    return hass.data[DOMAIN]["family"]

def get_current_rooms(hass):
    return hass.data[DOMAIN]["room_list"]

def get_current_devices(hass):
    return hass.data[DOMAIN]["device_list"]

def get_current_state(hass):
    return hass.data[DOMAIN]["state_list"]

def get_name_by_id(hass, device_id):
    return get_data_from_list(hass.data[DOMAIN]["device_list"], "deviceId", device_id, "deviceName", "")

def get_uid_by_id(hass, device_id):
    return get_data_from_list(hass.data[DOMAIN]["device_list"], "deviceId", device_id, "uid", "")

def get_model_by_id(hass, device_id):
    return get_data_from_list(hass.data[DOMAIN]["device_list"], "deviceId", device_id, "model", "")

def get_room_id_by_id(hass, device_id):
    return get_data_from_list(hass.data[DOMAIN]["device_list"], "deviceId", device_id, "roomId", "")

def get_name_by_uid(hass, uid):
    return get_data_from_list(hass.data[DOMAIN]["device_list"], "uid", uid, "deviceName", "")

def get_id_by_uid(hass, uid):
    return get_data_from_list(hass.data[DOMAIN]["device_list"], "uid", uid, "deviceId", "")

def get_state_by_id(hass, device_id):
    return get_data_from_list(hass.data[DOMAIN]["state_list"], "deviceId", device_id, "value1", 1)

def get_model_name_by_model_id(hass, model_id):
    return ORVIBO_SWITCH_MODEL.get(model_id,"")

def get_room_name_by_room_id(hass, room_id):
    return get_data_from_list(hass.data[DOMAIN]["room_list"], "roomId", room_id, "roomName", "")

def set_state_by_id(hass, device_id, state):
    return set_data_in_list(hass.data[DOMAIN]["state_list"], "deviceId", device_id, "value1", state)

def set_state_by_uid(hass, uid, state):
    return set_data_in_list(hass.data[DOMAIN]["state_list"], "uid", uid, "value1", state)

def set_current_floor(hass, floor):
    hass.data[DOMAIN]["floor"] = floor

def set_current_family(hass, family):
    hass.data[DOMAIN]["family"] = family

def set_current_rooms(hass, rooms):
    hass.data[DOMAIN]["room_list"] = rooms

def set_current_devices(hass, devices):
    hass.data[DOMAIN]["device_list"] = devices

def set_current_state(hass, state_list):
    hass.data[DOMAIN]["state_list"] = state_list

def set_device_state(hass, device_id, state):
    set_data_in_list(hass.data[DOMAIN]["state_list"], "deviceId", device_id, "state", state)
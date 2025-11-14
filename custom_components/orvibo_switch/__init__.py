# custom_components/wifi_switch/__init__.py
import logging
from datetime import timedelta
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_registry import EntityRegistry
from .coordinator import OrviboSwitchCoordinator
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)
from .config_flow import ConfigFlow
from .const import (
    PLATFORM_SWITCH,
    DOMAIN,
    SSL_HOST,
    SSL_PORT
)
from .https_client import HttpsClient
from .ssl_client import SSLClient

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [PLATFORM_SWITCH]
UPDATE_INTERVAL = timedelta(minutes=5)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """设置配置项，启动协调器"""
    # 1. 从 ConfigEntry 读取配置（用户名、MD5密码、服务器地址）
    username = entry.data["userName"]
    password_md5 = entry.data["passWord"]
    user_id = entry.data["userId"]

    data = {
        "username": username,
        "password": password_md5,
        "coordinator": None,  # 占位
        "floor": {},
        "family": {},
        "room_list": [],
        "device_list": [],
        "state_list": [],
    }
    hass.data[DOMAIN] = data

    # 创建协调器并首次拉取设备（关键：登录后主动请求设备）
    coordinator = OrviboSwitchCoordinator(
                        hass=hass,
                        username=username,
                        password=password_md5)
    # 等待协调器完成第一次数据更新（确保有设备数据）
    await coordinator.async_config_entry_first_refresh()


    # 存储核心对象到 hass.data（供实体和卸载时使用）
    data["coordinator"] = coordinator

    # 注册实体（动态创建设备对应的传感器/开关）
    # 方式：通过 async_forward_entry_setup 转发到 sensor 平台，由传感器类处理设备
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """卸载配置项"""
    data = hass.data[DOMAIN].pop(entry.entry_id)
    # await data["client"]._disconnect()
    # data["coordinator"].update_interval = None
    await data["coordinator"].async_unload_entry(entry)
    return await hass.config_entries.async_forward_entry_unload(entry, "switch")

# ------------------------------
# 设备删除清理
# ------------------------------
async def async_remove_config_entry_device(
    hass: HomeAssistant, config_entry: ConfigEntry, device_entry: dict
) -> bool:
    er: EntityRegistry = hass.helpers.entity_registry.async_get(hass)
    for entity in er.async_entries_for_config_entry(config_entry.entry_id):
        if entity.device_id == device_entry["id"]:
            er.async_remove(entity.entity_id)
    return True

# custom_components/orvibo_switch/switch.py
import logging
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .coordinator import OrviboSwitchCoordinator
from .functions import format_mac
from .hass import (
    get_room_name_by_room_id,
    get_model_name_by_model_id
)
from .const import(
    DOMAIN,
    MANUFACTURER,
    DEVICE_TYPE,
)

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant,
                            entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback):
    """设置开关实体"""
    coordinator: OrviboSwitchCoordinator = hass.data[DOMAIN]["coordinator"]

    # 创建开关实体
    entities = []
    for device_id in coordinator.device_states:
        entities.append(WifiSwitchDevice(coordinator, device_id))


    async_add_entities(entities)
    _LOGGER.info(f"添加了{len(entities)}个实体")

class WifiSwitchDevice(CoordinatorEntity, SwitchEntity):
    def __init__(self, coordinator: OrviboSwitchCoordinator, device_id):
        super().__init__(coordinator)

        device_state = coordinator.device_states[device_id]
        # 核心属性（依赖核心字段）
        self.device_id = device_id
        self._attr_unique_id = f"{DEVICE_TYPE}_{device_id}"
        self._attr_name = f"{device_state.get('device_name')}"
        self._attr_entity_category = None
        self._attr_icon = "mdi:power-plug"
        #self._attr_entity_picture = ""

        room_id = device_state.get("room_id")
        model_id = device_state.get('model')
        online = device_state.get("online")
        device_uid = device_state.get("device_uid")
        # --------------- 额外字段的使用 ---------------
        # 1. 设备属性（HA 界面「属性」面板中显示）

        self._attr_extra_state_attributes = {
            "room_name": get_room_name_by_room_id(coordinator.hass, room_id) if room_id else "",
            "online_status": "在线" if online else "离线",
            "mac_address": format_mac(device_uid),
            "product_name": get_model_name_by_model_id(coordinator.hass, model_id) if model_id else "",
            # "firmware_version": device_data["firmware"]
        }
        self._attr_device_info = {  # 绑定设备（关键，HA要求实体归属设备才易展示）
            "identifiers": {(f"{DEVICE_TYPE}_integration", f"device_{device_uid}")},
            "name": f"{self._attr_name}",
            "model": f"{model_id}",
            "manufacturer": MANUFACTURER,
            #"icon": "mdi:switch",
        }

        self.async_on_remove(
            self.coordinator.async_add_listener(self._handle_coordinator_update)
        )

    @property
    def is_on(self)->bool:
        if not self.coordinator.device_states:
            return False
        device_state = self.coordinator.get_device_state(self.device_id)
        return device_state

    async def async_turn_on(self, **kwargs):
        await self.coordinator.async_turn_on(self.device_id)

    async def async_turn_off(self, **kwargs):
        await self.coordinator.async_turn_off(self.device_id)

    @callback
    def _handle_coordinator_update(self) -> None:
        """当协调器通知更新时刷新状态"""
        self.async_write_ha_state()

    @property
    def should_poll(self) -> bool:
        return False        # 禁用轮询，依赖Coordinator推送更新

    async def async_added_to_hass(self):
        self.async_on_remove(self.coordinator.async_add_listener(self.async_write_ha_state))

    async def async_will_remove_from_hass(self):
        """实体移除时，停止Coordinator"""
        await self.coordinator.stop()
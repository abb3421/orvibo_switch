# custom_components/wifi_switch/coordinator.py
import logging
import asyncio

from typing import Dict, Any
from datetime import timedelta
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed
from homeassistant.helpers.event import async_track_time_interval

from.ssl_client import SSLClient
from .https_client import (
    HttpsClient
)


from .const import (
    SSL_HOST, SSL_PORT,
    DEVICE_NAME,
    UPDATE_INTERVAL,
    SSL_RECONNECT_INTERVAL
)

_LOGGER = logging.getLogger(__name__)


class OrviboSwitchCoordinator(DataUpdateCoordinator[Dict[str, Any]]):
    _initial_keys = {}
    def __init__(self, hass: HomeAssistant, username: str, password: str):
        self.username = username
        self.password = password
        self.hass = hass

        self.https_client = HttpsClient(
                        hass=hass,
                        username=username,
                        password=password
        )
        self.ssl_client = None

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DEVICE_NAME} Coordinator",
            update_interval=UPDATE_INTERVAL,
        )

        self.device_states = None

    async def _async_setup(self):
        """Set up the coordinator

        This is the place to set up your coordinator,
        or to load data, that only needs to be loaded once.

        This method will be called automatically during
        coordinator.async_config_entry_first_refresh.
        """
        try:
            # 1. 确保HTTPS登录（获取family_id）
            if not await self.https_client.ensure_login():
                raise UpdateFailed("HTTPS登录失败")

            # 2.首次拉取所有设备信息
            self.device_states = await self.https_client.update_state_list()

            # 2. 初始化全局SSL客户端（仅创建1次）
            await self._init_ssl_client()

            if self.ssl_client:
                # 启动SSL连接
                # self.hass.async_create_task(self.ssl_client.connect_and_login())
                await self.ssl_client.connect_and_login()
        except Exception as e:
            raise UpdateFailed(f"拉取设备状态失败: {str(e)}") from e

    async def _async_update_data(self) -> dict[str, list[Any]]:
        """定期拉取所有设备状态"""
        _LOGGER.info("正在获取设备及状态数据...")
        try:
            # 1. 确保HTTPS登录（获取family_id）
            if not await self.https_client.ensure_login():
                raise UpdateFailed("HTTPS登录失败")

            # 2. 获取设备最新状态（首次执行会同时拉取所有设备信息）
            self.device_states = await self.https_client.update_state_list()
            if not self.device_states:
                raise UpdateFailed("未获取到设备信息")
            return self.device_states
        except Exception as e:
            raise UpdateFailed(f"拉取设备状态失败: {str(e)}") from e

    async def _init_ssl_client(self):
        """初始化全局SSL客户端（仅执行1次）"""
        if self.ssl_client is not None:
            return

        # 确保HTTPS已获取family_id
        while True:
            if not self.https_client.family_id:
                _LOGGER.error("初始化SSL客户端失败：缺少family_id")
                await asyncio.sleep(1)
                continue
            break

        # 定义回调函数
        def on_session_id_obtained(session_id: str):
            """SSL session_id 回传回调"""
            _LOGGER.debug("为https_client设置session_id: %s", session_id)
            self.https_client.set_session_id(session_id)

        def on_status_update(device_id: str, status: int):
            """SSL状态推送回调"""
            _LOGGER.debug(f"从SSL获得更新设备")
            is_on = (status == 0)
            self.device_states[device_id]["state"] = is_on
            self.async_set_updated_data(self.device_states)
            _LOGGER.debug(f"SSL推送更新设备 {device_id} 状态: {status}")

        # 创建全局SSL客户端
        self.ssl_client = SSLClient(
            hass=self.hass,
            ssl_host=SSL_HOST,
            ssl_port=SSL_PORT,
            username=self.username,
            password=self.password,
            family_id=self.https_client.family_id,
            on_status_update=on_status_update,
            on_session_id_obtained=on_session_id_obtained,
            retry_interval = SSL_RECONNECT_INTERVAL
        )

    async def toggle_switch(self, device_id: str) -> bool:
        """发送控制指令"""
        if not self.ssl_client:
            _LOGGER.error("SSL客户端未初始化，无法发送控制指令")
            return False
        await self.ssl_client.async_toggle_device(device_id)
        return True

    async def async_turn_on(self, device_id: str) -> bool:
        """发送开启指令"""
        if not self.ssl_client:
            _LOGGER.error("SSL客户端未初始化，无法发送控制指令")
            return False
        await self.ssl_client.async_turn_on(device_id)
        return True

    async def async_turn_off(self, device_id: str) -> bool:
        """发送开启指令"""
        if not self.ssl_client:
            _LOGGER.error("SSL客户端未初始化，无法发送控制指令")
            return False
        await self.ssl_client.async_turn_off(device_id)
        return True

    def get_device_state(self, device_id):
        if self.device_states is None:
            return False
        return self.device_states.get(device_id).get("state")

    async def async_cleanup(self):
        """组件卸载时清理资源"""
        if self.ssl_client:
            await self.ssl_client.disconnect()
            _LOGGER.info("全局SSL连接已清理")

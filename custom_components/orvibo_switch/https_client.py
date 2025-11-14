#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import json
import ssl
import asyncio
import aiohttp
from homeassistant.core import HomeAssistant  #引入HA核心类
from typing import Optional, Any
from .packet import HomemateJsonData
from .const import (
    ID_UNSET,
    ORVIBO_SWITCH_MODEL,
    HTTP_HEADERS
)
from .hass import  (
    get_name_by_id,
    get_uid_by_id,
    get_model_by_id,
    get_room_id_by_id,
    deduplicate_by_key,
    set_current_floor,
    set_current_family,
    set_current_rooms,
    set_current_devices,
    set_current_state,
    get_current_devices,
    get_current_state,
)


# 配置日志
_LOGGER = logging.getLogger(__name__)


class HttpsClient():
    def __init__(
            self,
            hass: HomeAssistant,
            username: str,
            password: str
    ):
        self.hass = hass
        self.username = username
        self.password = password

        self.user_id = None
        self.session_id: Optional[str] = None  # 从SSL客户端接收
        self.access_token: Optional[str] = None
        self.family_id: Optional[str] = None  # 传递给SSL客户端
        self.family_name: Optional[str] = None
        self.room_id: Optional[str] = None

        self.proxy = ""
        self.session: aiohttp.ClientSession = None

    @property
    def is_logged_in(self) -> bool:
        """判断是否已登录（含令牌有效性）"""
        return self.access_token is not None and self.user_id is not None

    async def _create_ssl_context(self):
        """用 Python 标准库异步执行 SSL 同步操作，无需 hass 实例"""

        def _sync_create_context():
            """同步创建 SSL 上下文（原阻塞操作）"""
            ssl_context = ssl.create_default_context()
            # 保留你原有的调试配置（生产环境需改为 True + CERT_REQUIRED）
            ssl_context.check_hostname = False  # ⚠️ 仅调试用！
            ssl_context.verify_mode = ssl.CERT_NONE  # 配合调试关闭校验
            return ssl_context

        # 自动将同步函数放到线程池执行，不阻塞事件循环
        return await asyncio.to_thread(_sync_create_context)


    async def _connect(self):
        if self.session:
            return

        #ssl_context = ssl.create_default_context()
        ssl_context = await self._create_ssl_context()
        ssl_context.check_hostname = False  # ⚠️ 仅调试用！生产环境必须为 True
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        self.session = aiohttp.ClientSession(connector=connector)
        _LOGGER.info("HTTPS 会话创建成功")

    async def _disconnect(self):
        """关闭 HTTP 会话"""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
            _LOGGER.info("HTTPS 会话关闭")
        self.access_token = None

    def set_session_id(self, session_id: str):
        """接收SSL客户端的session_id（线程安全）"""
        self.session_id = session_id

    async def _send_request(self, url, data):
        if not self.session:
            raise ConnectionError("客户端未连接")
        if not data:
            resp = await self.session.get(
                url=url,
                headers=HTTP_HEADERS,
                skip_auto_headers=["Accept", "Connection"],
                proxy=self.proxy,
                ssl=False  # 如果证书有问题可临时关闭验证（生产环境建议修复）
            )
        else:
            resp = await self.session.post(
                url=url,
                timeout=aiohttp.ClientTimeout(total=10),
                data=data,
                headers=HTTP_HEADERS,
                skip_auto_headers=["Accept", "Connection"],
                proxy=self.proxy,
                ssl=False  # 如果证书有问题可临时关闭验证（生产环境建议修复）
            )
        resp.raise_for_status()
        data = await resp.text()
        resp = json.loads(data)
        return resp

    async def ensure_login(self) -> bool:
        """确保已登录（自动刷新 token）"""
        if not self.is_logged_in:
            if not self.session:
                await self._connect()
        assert self.session is not None

        if not self.access_token or not self.user_id:
            data = await self._fetch_access_token()
            if data:
                self.access_token = data.get("access_token", "")
                self.user_id = data.get("user_id", "")
        assert self.access_token and self.user_id

        if not self.family_id:
            data = await self._fetch_https_family()
            if data:
                self.family_id = data.get("familyId", "")
                self.family_name = data.get("familyName", "")
        assert self.family_id
        return True

    async def _fetch_access_token(self) -> dict:
        try:
            if self.session_id is None or self.session_id == bytes(ID_UNSET).decode('utf-8'):
                ret = HomemateJsonData.get_access_token_by_password(self.username, self.password)
            else:
                ret = HomemateJsonData.get_access_token_by_session_id(self.session_id)
            resp = await self._send_request(ret['url'], ret['data'])
            if "message" in resp:
                _LOGGER.error(resp["message"])
                return {}
            if "data" not in resp:
                _LOGGER.error("响应包中未找到[data]")
                return {}
            if "access_token" not in resp["data"]:
                _LOGGER.error("响应包中未找到[access_token]")
                return {}
            _LOGGER.info("HTTPS 申请ACCESS_TOKEN成功")
            return resp["data"]
        except Exception as e:
            _LOGGER.error("HTTPS请求失败: %s", e)
            return {}

    async def _fetch_https_family(self) -> dict:
        try:
            if not self.user_id or not self.access_token:
                _LOGGER.error("缺少[userId]或[accessToken]")
                return {}
            ret = HomemateJsonData.get_family_statistics_users(self.user_id, self.access_token)
            resp = await self._send_request(ret['url'], ret['data'])
            if "message" in resp:
                _LOGGER.error(resp["message"])
                return {}
            if "data" not in resp:
                _LOGGER.error("响应包中未找到[data]")
                return {}
            data = resp["data"]
            if isinstance(data, list) and len(data) > 0:
                data = data[0]
            if "familyId" not in data:
                _LOGGER.error("响应包中未找到[familyId]")
                return {}
            return data
        except Exception as e:
            _LOGGER.error("HTTPS 请求失败: %s", e)
            return {}

    async def _fetch_device_status(self, access_token, session_id, user_id, user_name, family_id) -> dict:
        try:
            ret = HomemateJsonData.get_devices_status(access_token=access_token,
                                                      session_id=session_id,
                                                      user_id=user_id,
                                                      user_name=user_name,
                                                      family_id=family_id)
            resp = await self._send_request(ret['url'], ret['data'])
            if "message" in resp:
                _LOGGER.error(resp["message"])
                return {}
            if "data" not in resp:
                _LOGGER.error("响应包中未找到[data]")
                return {}
            if "deviceStatus" not in resp["data"]:
                _LOGGER.error("响应包中未找到[deviceStatus]")
                return {}
            return resp["data"]
        except Exception as e:
            _LOGGER.error("HTTPS 请求失败: %s", e)
            return {}

    async def _fetch_https_homepage(self, family_id, user_id, access_token) -> dict:
        try:
            ret = HomemateJsonData.get_homepage_data(family_id=family_id,
                                                     user_id=user_id,
                                                     access_token=access_token)
            resp = await self._send_request(ret['url'], ret['data'])
            if "message" in resp:
                _LOGGER.error(resp["message"])
                return {}
            if "data" not in resp:
                _LOGGER.error("响应包中未找到[data]")
                return {}
            if "device" not in resp["data"]:
                _LOGGER.error("响应包中未找到[device]")
                return {}
            return resp["data"]
        except Exception as e:
            _LOGGER.error("HTTPS 请求失败: %s", e)
            return {}

    async def fetch_device_state(self)->bool:
        """周期性获取设备状态，所需参数：access_token,session_id,user_id,username,family_id"""
        try:
            if self.session_id == bytes(ID_UNSET).decode('utf-8'):
                _LOGGER.error("session_id 缺失")
                return False

            if not await self.ensure_login():
                _LOGGER.error("HTTPS 未登录")
                return False
            data = await self._fetch_device_status(
                                    self.access_token,
                                    self.session_id,
                                    self.user_id,
                                    self.username,
                                    self.family_id)
            assert data
            device = data.get("device", {})
            if isinstance(device, list) and len(device) > 0:
                device = device[0]
            self.room_id = device.get("roomId", "")
            _state_list = data.get("deviceStatus", {})
            if _state_list:
                set_current_state(self.hass, _state_list)
                return True
            return False
        except aiohttp.ClientError as e:
            _LOGGER.error("拉取设备状态失败（网络错误）：%s",e)
            return False
        except Exception as e:
            _LOGGER.error("拉取设备状态失败：%s",e)
            return False

    async def fetch_homepage_data(self)->bool:
        """获取首页数据，所需参数：family_id,user_id,access_token"""
        try:
            if not await self.ensure_login():
                _LOGGER.error("HTTPS 未登录")
                return False

            data = await self._fetch_https_homepage(self.family_id, self.user_id, self.access_token)
            assert data

            device_list = data.get("device", {})
            state_list = data.get("deviceStatus", {})

            set_current_floor(self.hass, data.get("floor", {})[0])
            set_current_family(self.hass, data.get("familyConfig", {})[0])
            set_current_rooms(self.hass, data.get("room", []))
            set_current_devices(self.hass, device_list)
            set_current_state(self.hass, state_list)

            # 只保留switch类型
            device_list = [item for item in device_list if item.get('model') in ORVIBO_SWITCH_MODEL.keys()]
            if not device_list:
                return False
            set_current_devices(self.hass, device_list)
            switch_id_list = [item['deviceId'] for item in device_list if 'deviceId' in item]
            if switch_id_list:
                state_list = [item for item in state_list if item.get('deviceId') in switch_id_list]
            state_list = deduplicate_by_key(state_list, 'deviceId')
            if state_list:
                set_current_state(self.hass, state_list)
            return True
        except aiohttp.ClientError as e:
            _LOGGER.error("获取主页数据失败（网络错误）：%s",e)
            return False
        except Exception as e:
            _LOGGER.error("获取主页数据失败：%s", e)
            return False

    async def update_state_list(self) -> None | dict[str, list[Any]]:
        """
        拉取设备列表（核心方法）
        """
        try:
            device_list = get_current_devices(self.hass)
            if not device_list or not self.session_id:
                if not await self.fetch_homepage_data():
                    _LOGGER.error("拉取设备失败")
                    return {}
                device_list = get_current_devices(self.hass)
            else:
                await self.fetch_device_state()
            state_list = get_current_state(self.hass)


            if not device_list or not state_list:
                _LOGGER.error("拉取设备失败")
                return {}

            _LOGGER.debug("获取到%d个设备，以及%d个设备状态", len(device_list), len(state_list))

            device_states = {}
            for state in state_list:
                device_id = state.get("deviceId", "")
                if not device_id:
                    continue
                status = state.get("value1", 1)
                status = False if status == 1 else True
                online = state.get("online", 1)

                device_name = get_name_by_id(self.hass, device_id)
                device_uid = get_uid_by_id(self.hass, device_id)
                device_model = get_model_by_id(self.hass, device_id)
                room_id = get_room_id_by_id(self.hass, device_id)
                if device_name:
                    device_states[device_id] = {
                        "device_id": device_id,
                        "device_name": device_name,
                        "device_uid": device_uid,
                        "model": device_model,
                        "state": status,
                        "online": online,
                        "room_id": room_id,
                    }
            return device_states
        except aiohttp.ClientError as e:
            _LOGGER.error("拉取设备失败（网络错误）：%s", e)
            return None
        except Exception as e:
            _LOGGER.error("拉取设备失败：%s", e)
            return None

def test():
    print("Test")


if __name__ == '__main__':
    test()

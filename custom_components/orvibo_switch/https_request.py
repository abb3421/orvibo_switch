#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import json
import asyncio
from .packet import HomemateJsonData
import ssl
import aiohttp
from .const import (
    ID_UNSET,
    ORVIBO_SWITCH_MODEL,
    HTTP_HEADERS
)

# 配置日志
_LOGGER = logging.getLogger(__name__)


class AsyncHttpsClient():
    def __init__(self,username, password,  user_id):
        self.username = username
        self.password = password
        self.session_id = None
        self.access_token = None
        self.user_id = user_id
        self.family_id = None
        self.family_name = None
        self.room_id = None

        self.floor = {}
        self.family_config = {}
        self.device_list = []
        self.room_list = []
        self.device_status = []

        self.proxy = ""
        self.session: aiohttp.ClientSession = None

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


    async def async_connect(self):
        if self.session:
            return

        #ssl_context = ssl.create_default_context()
        ssl_context = await self._create_ssl_context()
        ssl_context.check_hostname = False  # ⚠️ 仅调试用！生产环境必须为 True
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        self.session = aiohttp.ClientSession(connector=connector)
        _LOGGER.info("HTTPS 会话创建成功")

    async def async_disconnect(self):
        """关闭 HTTP 会话"""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
            _LOGGER.info("HTTPS 会话关闭")
        self.access_token = None

    def set_session_id(self, session_id):
        self.session_id = session_id

    async def _send_https_request(self, url, data):
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

    async def _fetch_access_token(self, session_id) -> dict:
        try:
            if self.session_id is None:
                ret = HomemateJsonData.get_access_token_by_password(self.username, self.password)
            else:
                ret = HomemateJsonData.get_access_token_by_session_id(session_id)
            resp = await self._send_https_request(ret['url'], ret['data'])
            if "message" in resp:
                _LOGGER.error(resp["message"])
                return {}
            if "data" not in resp:
                _LOGGER.error("响应包中未找到[data]")
                return {}
            if "access_token" not in resp["data"]:
                _LOGGER.error("响应包中未找到[access_token]")
                return {}
            return resp["data"]
        except Exception as e:
            _LOGGER.error("HTTPS请求失败: %s", e)
            return {}

    async def _fetch_https_family(self, user_id, access_token) -> dict:
        try:
            ret = HomemateJsonData.get_family_statistics_users(user_id, access_token)
            resp = await self._send_https_request(ret['url'], ret['data'])
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
            resp = await self._send_https_request(ret['url'], ret['data'])
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
            resp = await self._send_https_request(ret['url'], ret['data'])
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

    async def fetch_family_id(self):
        try:
            if not self.access_token or not self.user_id:
                if self.session_id == bytes(ID_UNSET).decode('utf-8'):
                    self.session_id = None
                data = await self._fetch_access_token(self.session_id)
                assert data
                self.access_token = data.get("access_token", "")
                self.user_id = data.get("user_id", "")

            data = await self._fetch_https_family(self.user_id, self.access_token)
            assert data

            self.family_id = data.get("familyId", "")
            self.family_name = data.get("familyName","")
            return self.family_id
        except aiohttp.ClientError as e:
            _LOGGER.error("获取familyId失败（网络错误）：%s",e)
            return None
        except Exception as e:
            _LOGGER.error("获取familyId失败：%s", e)
            return None

    async def fetch_device_state(self):
        try:
            if self.session_id == bytes(ID_UNSET).decode('utf-8'):
                _LOGGER.error("session_id 缺失")
                return {}
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
            device_status = data.get("deviceStatus", {})
            assert device_status
            # return device_status
            _device_status = []
            for dev in device_status:
                deviceId = dev.get("deviceId", "")
                value1 = dev.get("value1", 1)
                state = True if value1 == 0 else False
                name = dev.get("name", "")
                _dev = {
                        "deviceId": deviceId,
                        "deviceMac": dev.get("uid", ""),
                        "deviceName": name if name else dev.get("uid", ""),
                        "roomId": self.room_id,
                        "state": state,
                        "online": dev.get("online", 0),
                    }
                _device_status.append(_dev)
            return _device_status
        except aiohttp.ClientError as e:
            _LOGGER.error("拉取设备状态失败（网络错误）：%s",e)
            return None
        except Exception as e:
            _LOGGER.error("拉取设备状态失败：%s",e)
            return None

    async def fetch_homepage_data(self):
        try:
            if not self.access_token or not self.user_id:
                if self.session_id == bytes(ID_UNSET).decode('utf-8'):
                    self.session_id = None
                data = await self._fetch_access_token(self.session_id)
                assert data
                self.access_token = data.get("access_token", "")
                self.user_id = data.get("user_id", "")
            if not self.family_id:
                await self.fetch_family_id()

            data = await self._fetch_https_homepage(self.family_id, self.user_id, self.access_token)
            assert data

            self.floor = data.get("floor", "")[0]
            self.family_config = data.get("familyConfig", {})[0]
            self.device_list = data.get("device", [])
            self.room_list = data.get("room", [])
            self.device_status = data.get("deviceStatus", {})
            return self
        except aiohttp.ClientError as e:
            _LOGGER.error("获取主页数据失败（网络错误）：%s",e)
            return None
        except Exception as e:
            _LOGGER.error("获取主页数据失败：%s", e)
            return None

    @classmethod
    def update_device_state(cls, device_list, device_status):
        assert device_list
        assert device_status
        for status in device_status:
            device_id = status.get("deviceId", "")
            if not device_id:
                continue
            for dev in device_list:
                if device_id == dev.get("deviceId", ""):
                    if "state" in status:
                        dev["state"] = status.get("state", False)
                    if "value1" in status:
                        dev["state"] = True if status.get("value1", 1)==0 else False
                    if "online" in status:
                        dev["online"] = status.get("online", 0)


    async def async_get_device_list(self) -> list[dict]:
        """
        拉取设备列表（核心方法）
        """
        try:
            device_list = []
            if not self.device_list:
                await self.fetch_homepage_data()
            assert self.device_list
            for dev in self.device_list:
                if ORVIBO_SWITCH_MODEL and dev.get("model", "") not in ORVIBO_SWITCH_MODEL:
                    continue
                _dev = {
                    "deviceId": dev.get("deviceId", ""),
                    "deviceMac": dev.get("uid", ""),
                    "deviceName": dev.get("deviceName", ""),
                    "roomId": dev.get("roomId", ""),
                }
                device_list.append(_dev)

            AsyncHttpsClient.update_device_state(device_list, self.device_status)

            if self.session_id:
                device_status = await self.fetch_device_state()
                AsyncHttpsClient.update_device_state(device_list, device_status)


            return device_list
        except aiohttp.ClientError as e:
            raise f"拉取设备失败（网络错误）：{str(e)}"
        except Exception as e:
            raise f"拉取设备失败：{str(e)}"

def test():
    print("Test")


if __name__ == '__main__':
    test()

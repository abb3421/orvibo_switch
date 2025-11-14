#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import ssl
import asyncio
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Callable
from homeassistant.core import HomeAssistant  #引入HA核心类
from .packet import (HomematePacket, HomemateJsonData)

from.hass import (
    get_uid_by_id,
    get_id_by_uid,
    get_name_by_uid,
    get_current_devices,
    get_current_state,
    get_state_by_id,
    set_state_by_id,
    set_state_by_uid
)

from .const import (
    SSL_HOST, SSL_PORT, CLIENT_CERT, CLIENT_KEY, SERVER_CA, ID_UNSET, DEFAULT_KEY,
    SSL_MAX_RECONNECT_ATTEMPTS,
    CMD_HELLO, CMD_LOGIN, CMD_STATE_UPDATE, CMD_CONTROL, CMD_HEARTBEAT, CMD_HANDSHAKE,
)

_LOGGER = logging.getLogger(__name__)

class SSLClient:
    _initial_keys = {}
    """独立的SSL长连接客户端：处理SSL连接、登录、控制指令发送、状态监听"""
    def __init__(
        self,
        hass: HomeAssistant,
        ssl_host: str,
        ssl_port: int,
        username: str,
        password: str,
        family_id: str,
        on_session_id_obtained: Callable[[str], None],
        on_status_update: Callable[[str, int], None],
        heartbeat_interval: int = 30,
        retry_interval: int = 5
    ):
        """
        初始化SSL长连接客户端
        :param hass: Home Assistant实例（用于线程池执行同步操作）
        :param ssl_host: SSL服务器地址
        :param ssl_port: SSL服务器端口
        :param username: 登录用户名
        :param password: 登录密码
        :param family_id: 家庭id号
        :param on_session_id_obtained: 获取到session_id后回调
        :param on_status_update: 状态更新回调（参数：device_id, status）
        :param heartbeat_interval: 心跳包发送间隔（秒）
        :param retry_interval: 重连间隔（秒）
        """
        self.hass = hass  # 存储HA实例
        self.ssl_host = ssl_host
        self.ssl_port = ssl_port
        self.username = username
        self.password = password
        self.family_id = family_id

        self.on_session_id_obtained = on_session_id_obtained
        self.on_status_update = on_status_update
        self.heartbeat_interval = heartbeat_interval
        self.retry_interval = retry_interval

        BASE_DIR = Path(__file__).parent.resolve()
        self.certfile=BASE_DIR / CLIENT_CERT
        self.keyfile=BASE_DIR / CLIENT_KEY
        self.cafile=BASE_DIR / SERVER_CA

        # 连接状态
        self.ssl_context = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.session_id: Optional[str] = None
        self.session_key: Optional[bytes] = None
        self.connected: bool = False
        self._listening_task: Optional[asyncio.Task] = None

    @classmethod
    def add_key(cls, session_id: str, key: bytes):
        cls._initial_keys[session_id] = key

    @classmethod
    def get_key(cls, session_id:str) -> bytes:
        try:
            return cls._initial_keys[session_id]
        except KeyError:
            return DEFAULT_KEY.encode("utf-8")

    @property
    def is_connected(self):
        return self.connected

    async def _create_ssl_context(self):
        """异步创建SSL上下文（通过HA线程池执行同步操作）"""
        def _sync_create_context():
            try:
                if not os.path.exists(self.certfile):
                    raise FileNotFoundError("找不到证书文件：%s", self.certfile)
                if not os.path.exists(self.keyfile):
                    raise FileNotFoundError("找不到密钥文件：%s", self.keyfile)
                if not os.path.exists(self.cafile):
                    raise FileNotFoundError("找不到CA证书文件：%s", self.cafile)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                context.load_verify_locations(cafile=self.cafile)
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                # self.ssl_context = context
                return context
            except Exception as e:
                _LOGGER.error(f"创建SSL上下文失败: {str(e)}")
                raise

        return await self.hass.async_add_executor_job(_sync_create_context)

    async def _connect(self):
        """建立SSL连接（消除阻塞警告）（先确保上下文已创建）"""
        if self.connected:
            return True
        try:
            if not self.ssl_context:
                self.ssl_context = await self._create_ssl_context()
            _LOGGER.debug("SSL正在连接...")
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self.ssl_host,
                    port=self.ssl_port,
                    ssl=self.ssl_context,
                    server_hostname=self.ssl_host
                ),
                timeout=10.0  # 10秒超时
            )
            self._update_activity("SSL连接成功")
            self.connected = True
            return True
        except asyncio.TimeoutError:
            _LOGGER.error("SSL连接服务器 [%s:%s] 超时", SSL_HOST, SSL_PORT)
            return False
        except OSError as e:
            _LOGGER.error("SSL连接发生IO错误: %s", e)
            return False
        except Exception as e:
            _LOGGER.error("SSL连接失败: %s", e)
            return False

    async def _disconnect(self):
        """退出监听任务并断开连接"""
        if self._listening_task and not self._listening_task.done():
            self._listening_task.cancel()
            try:
                await self._listening_task
            except asyncio.CancelledError:
                pass

        if self.writer and not self.writer.is_closing():
            _LOGGER.info("SSL正在断开已有连接...")
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                _LOGGER.debug("关闭SSL连接超时")
            except Exception as e:
                _LOGGER.debug("关闭SSL连接失败: %s", e)

        self.reader = None
        self.writer = None
        self.session_id = None
        self.session_key = None
        self.connected = False
        _LOGGER.info(f"SSL连接已断开")

    async def _reconnect(self):
        """重连逻辑"""
        try:
            await self._disconnect()
        except Exception as e:
            _LOGGER.error("错误: %s", e)

        if self.retry_interval > 0:
            _LOGGER.info(f"{self.retry_interval}秒后尝试重连...")
            await asyncio.sleep(self.retry_interval)
            await self.connect_and_login()

    async def connect_and_login(self):
        """建立连接并完成登录流程"""
        if self.connected:
            return True
        for retry in range(SSL_MAX_RECONNECT_ATTEMPTS):
            try:
                # 建立 SSL 连接
                _LOGGER.info("SSL正在连接和登录...")
                self.connected = await self._connect()
                if self.connected:
                    # 发送获取会话密钥请求
                    await self._send_hello()

                    # 启动监听任务
                    self._listening_task = self.hass.async_create_background_task(
                        self._listen_loop(),
                        name="server_response_listener")

                    # 等待获取session_id和session_key
                    await asyncio.sleep(3)
                    # SSL 登录
                    await self._send_login()
                    return True
            except Exception as e:
                _LOGGER.warning(f"连接/登录重试 {retry+1}/{SSL_MAX_RECONNECT_ATTEMPTS}")
                await asyncio.sleep(self.retry_interval * (retry + 1))  # 指数退避
        return False

    async def _send_packet(self, data: dict, key: bytes):
        """加密并发送数据包"""
        try:
            if key == DEFAULT_KEY.encode("utf-8"):
                packet_type = bytes([0x70, 0x6b])   #pk开头的使用默认密钥加密
                self.session_id = bytes(ID_UNSET).decode("utf-8")
            else:
                packet_type = bytes([0x64, 0x6b])   #dk开头的使用服务器会话密钥加密
            ciphertext = HomematePacket.build_packet(
                packet_type=packet_type,
                key=key,
                session_id=self.session_id.encode("utf-8"),
                payload=data
            )
            if not self.writer:
                await self._reconnect()
            self._update_activity("发送指令")
            self.writer.write(ciphertext)
            await self.writer.drain()
        except Exception as e:
            _LOGGER.error("发送失败: %s", e)
            if 'lost' in str(e) or 'close' in str(e) or '_write_appdata' in str(e):
                await self._reconnect()

    async def _send_hello(self):
        """发送申请会话密钥请求"""
        payload = HomemateJsonData.ssl_get_session()
        await self._send_packet(payload, DEFAULT_KEY.encode("utf-8"))

    async def _send_login(self):
        """发送登录请求"""
        if not self.connected:
            _LOGGER.warning(f"未建立SSL连接，无法登录")
            return False
        payload = HomemateJsonData.ssl_login(username=self.username,
                                             password_md5=self.password,
                                             family_id=self.family_id)
        if self.session_key and self.session_key != DEFAULT_KEY.encode("utf-8"):
            await self._send_packet(payload, self.session_key)
            return True
        return False

    async def _send_control(self, device_id: str, device_uid: str, state: int):
        """发送开关控制指令"""
        await self.connect_and_login()
        assert device_uid

        payload = HomemateJsonData.ssl_switch_control(username=self.username,
                                                      device_id=device_id,
                                                      device_mac=device_uid,
                                                      state=state)
        if self.session_key and self.session_key != DEFAULT_KEY.encode("utf-8"):
            for retry in range(SSL_MAX_RECONNECT_ATTEMPTS):
                if self.connected:
                    await self._send_packet(payload, self.session_key)
                    return True
                _LOGGER.warning("SSL连接未建立，2秒后重试...")
                await asyncio.sleep(2)
        _LOGGER.warning("无法给[%s]发送控制指令:%s", device_id, state)
        return False

    async def _listen_loop(self):
        """持续监听服务器消息"""
        _LOGGER.debug("已进入SSL服务器监听状态")
        while True:
            try:
                # 读取42字节长度的头部数据
                header_data = await self.reader.readexactly(42)
                if not header_data:
                    await asyncio.sleep(1)
                    continue
                length = HomematePacket.parse_length(header_data)
                ciphertext = await self.reader.readexactly(length-42)
                if self.session_key is None:
                    self.session_key = DEFAULT_KEY.encode("utf-8")
                # 解密
                packet = HomematePacket(header_data+ciphertext, {self.session_id: self.session_key})
                self.session_id = bytes(packet.session_id).decode('utf-8')
                data = packet.json_payload

                cmd = data.get("cmd")
                if cmd :
                    self._update_activity(f"收到服务器响应: cmd={cmd}")
                if cmd == CMD_HELLO:
                    await self._handle_hello(data)
                elif cmd == CMD_LOGIN:
                    await self._handle_login(data)
                elif cmd == CMD_CONTROL:
                    await self._handle_control(data)
                elif cmd == CMD_STATE_UPDATE:
                    await self._handle_state_update(data)
                elif cmd == CMD_HANDSHAKE:
                    pass  # 忽略握手
                elif cmd == CMD_HEARTBEAT:
                    pass  # 忽略心跳
                else:
                    _LOGGER.warning("未知命令: %s", cmd)
                    _LOGGER.debug("响应包: %s", data)
            except asyncio.IncompleteReadError as e:
                _LOGGER.warning("读取失败: %s，连接中断: %s", e, self.reader.at_eof())
                break
            except asyncio.TimeoutError as e:
                _LOGGER.warning("等待超时: %s，连接中断: %s", e, self.reader.at_eof())
                break
            except ConnectionError as e:
                _LOGGER.warning("连接错误: %s，连接中断: %s", e, self.reader.at_eof())
                break
            except asyncio.CancelledError:
                _LOGGER.debug("任务已取消, 退出SSL服务器监听状态")
                await self._disconnect()
                return
            except Exception as e:
                _LOGGER.error("接收错误: %s，连接中断: %s", e, self.reader.at_eof())
                break
        _LOGGER.debug("已退出SSL服务器监听状态")
        # 断开后重连
        await self._reconnect()

    async def _handle_hello(self, data: dict):
        """处理会话密钥响应"""
        self.session_key = str(data.get("key")).encode("utf-8")
        SSLClient.add_key(self.session_id, self.session_key)
        _LOGGER.debug("SSL 会话创建成功, sessionId: %s, sessionKey: %s",self.session_id, data.get("key"))
        self.on_session_id_obtained(self.session_id)

    async def _handle_login(self, data: dict):
        """处理登录响应"""
        if "userId" in data:
            _LOGGER.info("SSL 登录成功，userId: %s",data.get("userId"))
            self._connected = True
            # 可选：请求当前状态
        else:
            _LOGGER.error("SSL 登录失败: %s", data.get("msg"))

    async def _handle_control(self, data: dict):
        """处理开关控制响应"""
        if "uid" in data:
            uid = data.get("uid") #uid其实是switch的mac地址
            device_name = get_name_by_uid(self.hass, uid)
            _LOGGER.info("开关[%s]控制成功", device_name if device_name else uid)
        else:
            _LOGGER.info("开关控制失败: %s", data.get("msg"))

    async def _handle_state_update(self, data: dict):
        """处理状态更新推送"""
        if data.get("respByAcc"):
            uid = data.get("uid","")
            device_state = data.get("value1",1)
            device_name = get_name_by_uid(self.hass, uid)
            device_id = get_id_by_uid(self.hass, uid)
            if set_state_by_uid(self.hass, uid, device_state):
                _LOGGER.info("开关[%s]状态更新为: %s", device_name, "关闭" if device_state==1 else "开启")
            # 触发 HA 更新 UI
            self.on_status_update(device_id, device_state)

    async def _handle_heartbeat(self, data: dict):
        """处理心跳包（未实现）"""
        if "uid" in data:
            uid = data.get("uid","")
            return {
            'utc': int(time.time())
        }
        _LOGGER.debug(f"heartbeat: {data}")

    async def _handle_handshake(self, data: dict):
        """处理握手包（未实现）"""
        if 'localIp' in data:
            entity_id = data['localIp'].replace('.', '_')

        _LOGGER.debug(f"handshark: {data}")

    async def async_toggle_device(self, device_id: str):
        """切换设备状态"""
        state_list = get_current_state(self.hass)
        current = get_state_by_id(self.hass, device_id)
        new_state = 1 if current == 0 else 0
        device_list = get_current_devices(self.hass)
        uid = get_uid_by_id(self.hass, device_id)
        if uid:
            await self._send_control(device_id, new_state)
            set_state_by_id(self.hass, uid, new_state)

    async def async_turn_on(self, device_id: str):
        """打开设备"""
        uid = get_uid_by_id(self.hass, device_id)
        if uid:
            await self._send_control(device_id, uid, 0)
            set_state_by_id(self.hass, device_id, 0)

    async def async_turn_off(self, device_id: str):
        """关闭设备"""
        uid = uid = get_uid_by_id(self.hass, device_id)
        if uid:
            await self._send_control(device_id, uid, 1)
            set_state_by_id(self.hass, device_id, 1)

    def _update_activity(self, msg):
        """更新最后活跃时间"""
        self._last_active_time = datetime.now()
        _LOGGER.debug("%s, 激活时间：%s", msg, self._last_active_time)

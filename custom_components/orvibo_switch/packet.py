#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pip install hexdump cryptography

import json
import struct
import binascii
import logging
import base64
from hexdump import hexdump
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding
from .functions import (
    text_utils_is_empty,
    hmac_sha256,
    generate_timestamp,
    generate_serial,
    generate_uuid,
)

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

_LOGGER = logging.getLogger(__name__)

from .const import (
    DEFAULT_KEY, SIGN_KEY, MAGIC,UPLOAD_LOG_URL,HTTPS_HOST,FETCH_LOG_URL,HTTP_HEADERS,
    SOFTWARE_NAME, SOFTWARE_VER, SOFTWARE_VERSION, SYS_VERSION,HARDWARE_VERSION, LANGUAGE, PHONE_NAME, DEBUG_INFO,
    CMD_HELLO, CMD_LOGIN,CMD_CONTROL,
)

proxies = {
}


class PacketLog:

    log = []
    logfile = None

    OUT = "out"
    IN = "in"

    @classmethod
    def enable(cls, logfile):
        cls.logfile = logfile

    @classmethod
    def record(cls, data, direction, keys=None, client=None):
        if cls.logfile is not None:
            cls.log.append({
                'data': base64.b64encode(data).decode('utf-8'),
                'direction': direction,
                'keys': {
                    k: base64.b64encode(v).decode('utf-8') for k, v in keys.items()
                },
                'client': client
            })

            with open(cls.logfile, 'w') as f:
                json.dump(cls.log, f)

class HomematePacket:
    def __init__(self, data: bytes, keys: dict):
        self.raw = data
        if not data:
            self.magic = MAGIC  # hd
            self.length = 0
            self.packet_type = bytes([0x70, 0x6b])  # pk
            self.crc = None
            self.session_id = None
            self.json_payload = None
            return

        try:
            # Check the magic bytes
            self.magic = data[0:2]
            assert self.magic == MAGIC

            # Check the 'length' field
            self.length = struct.unpack(">H", data[2:4])[0]
            assert self.length == len(data)

            # Check the packet type
            self.packet_type = data[4:6]
            assert self.packet_type == bytes([0x70, 0x6b]) or \
                self.packet_type == bytes([0x64, 0x6b])

            # Check the CRC32
            self.crc = binascii.crc32(data[42:]) & 0xFFFFFFFF
            data_crc = struct.unpack(">I", data[6:10])[0]
            assert self.crc == data_crc
        except AssertionError:
            _LOGGER.error("Bad packet:")
            hexdump(data)
            raise

        self.session_id = data[10:42]

        current_key = DEFAULT_KEY.encode("utf-8")
        if self.packet_type == bytes([0x64, 0x6b]):
            current_key = keys[self.session_id.decode('utf-8')]

        #self.json_payload = self.decrypt_payload(keys[self.packet_type[0]], data[42:])
        if data[42:]:
            self.json_payload = self.decrypt_payload(current_key, data[42:])
        else:
            self.json_payload = None

    @classmethod
    def parse_length(cls, data: bytes):
        try:
            # Check the magic bytes
            magic = data[0:2]
            assert magic == MAGIC
            length = struct.unpack(">H", data[2:4])[0]
            return length
        except Exception as e:
            _LOGGER.error("Bad packet: %s", str(e))
            raise

    @classmethod
    def decrypt_payload(cls, key: bytes, encrypted_payload: bytes):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        ).decryptor()
        data = decryptor.update(encrypted_payload)
        unpadder = padding.PKCS7(128).unpadder()
        unpad = unpadder.update(data)
        unpad += unpadder.finalize()

        # sometimes payload has an extra trailing null
        if unpad[-1] == 0x00:
            unpad = unpad[:-1]
        return json.loads(unpad.decode('utf-8'))

    @classmethod
    def encrypt_payload(cls, key: bytes, payload: str):
        data = payload.encode('utf-8')

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        ).encryptor()

        encrypted_payload = encryptor.update(padded_data)
        return encrypted_payload

    @classmethod
    def build_packet(cls, packet_type: bytes, key: bytes, session_id: bytes, payload: dict):
        payload_str = json.dumps(payload, separators=(',', ':'))
        encrypted_payload = cls.encrypt_payload(key, payload_str)
        crc = struct.pack('>I', binascii.crc32(encrypted_payload) & 0xFFFFFFFF)
        length = struct.pack('>H', len(encrypted_payload) + len(MAGIC + packet_type + crc + session_id) + 2)

        packet = MAGIC + length + packet_type + crc + session_id + encrypted_payload
        return packet

class HomemateJsonData:
    def __init__(self, data: bytes):
        self.raw = data

    @classmethod
    # ssl请求获取sessionId的payload
    def ssl_get_session(cls):
        serial = generate_serial()
        uniSerial = generate_serial(use_time=True)
        identifier = generate_uuid()[:12]

        payload = {
            "source": SOFTWARE_NAME,
            "softwareVersion": SOFTWARE_VERSION,
            "sysVersion": SYS_VERSION,
            "hardwareVersion": HARDWARE_VERSION,
            "language": LANGUAGE,
            "identifier": identifier,
            "phoneName": PHONE_NAME,
            "cmd": CMD_HELLO,
            "serial": serial,
            "clientType": 1,
            "uniSerial": uniSerial,
            "serverRecord": False,
            "ver": SOFTWARE_VER,
            "debugInfo": DEBUG_INFO,
        }
        return payload

    @classmethod
    # ssl请求控制switch状态
    def ssl_switch_control(cls,
                           username: str,
                           device_id: str,
                           device_mac: str,
                           state: int):
        serial = generate_serial()
        uniSerial = generate_serial(use_time=True)
        payload = {
            "uid": device_mac,
            "userName": username,
            "deviceId": device_id,
            "groupId": "",
            "order": "on" if state==0 else "off",
            "value1": 1 if state else 0,
            "value2": 0,
            "value3": 0,
            "value4": 0,
            "delayTime": 0,
            "qualityOfService": 1,
            "defaultResponse": 1,
            "propertyResponse": 0,
            "cmd": CMD_CONTROL,
            "serial": serial,
            "clientType": 1,
            "uniSerial": uniSerial,
            "serverRecord": False,
            "ver": SOFTWARE_VER,
            "debugInfo": DEBUG_INFO,
        }
        return payload

    @classmethod
    def ssl_login(cls,
                  username: str,
                  password_md5: str,
                  family_id: str):
        serial = generate_serial()
        uniSerial = generate_serial(use_time=True)
        payload = {
            "userName":username,
            "password":password_md5,
            "familyId":family_id,
            "type":4,
            "needAccountDetailError":True,
            "cmd":CMD_LOGIN,
            "serial":serial,
            "clientType":1,
            "uniSerial":uniSerial,
            "serverRecord":False,
            "ver": SOFTWARE_VER,
            "debugInfo": DEBUG_INFO,
        }
        return payload


    @classmethod
    # 发送http/https请求时对数据包的签名
    def create_sign(cls, params, key=SIGN_KEY):
        # 1. 按key的自然顺序排序
        sorted_keys = sorted(params.keys())

        # 2. 拼接字符串
        sb = []
        for k in sorted_keys:
            value = params[k]
            if not text_utils_is_empty(value):
                sb.append(f"{k}={value}&")

        # 添加密钥
        sb.append(f"key={key}")
        sign_str = ''.join(sb)
        # _LOGGER.debug(f"待加密字符串: {sign_str}")

        # 3. 使用HmacSHA256加密
        sign = hmac_sha256(key, sign_str)

        # _LOGGER.debug(f"生成的签名: {sign}")
        return sign

    @classmethod
    # 上传switch控制日志的数据包及URL（https）
    def upload_log(cls, user_json, device_json, switch_on=True):
        url = UPLOAD_LOG_URL
        timestamp = generate_timestamp()
        value1 = 0 if switch_on else 1
        order = 'on' if switch_on else 'off'

        data_json = {
            "ctrlInfo": {
                "expand": [],
                "id": device_json['id'],
                "location": device_json['location'],
                "name": device_json['name'],
                "param": {
                    "value2": 0,
                    "value1": value1,
                    "value4": 0,
                    "value3": 0,
                    "delayTime": 0,
                    "order": order
                },
                "type": "device"
            },
            "result": {"errCode": 0},
            "serial": timestamp,
            "state": 0,
            "trigInfo": {
                "account": "xxx",
                "id": "",
                "location": {},
                "name": "Tesla phone",
                "param": {},
                "type": "screen"
            }
        }
        data_str = json.dumps(data_json, ensure_ascii=False, indent=None, separators=(',', ':'))

        reqData_json = [
            {
                "appId": 0,
                "data": data_str,  # 传入带 1 级转义的 data 字符串
                "familyId": user_json['familyId'],
                "source": 1,
                "timestamp": timestamp,
                "type": 6,
                "userId": user_json['userId'],
                "ver": "5.1.4.302"
            }
        ]
        reqData_str = json.dumps(reqData_json, ensure_ascii=False, indent=None, separators=(',', ':'))

        timestamp = generate_timestamp()
        random_str = generate_uuid()
        params = {
            "timestamp": str(timestamp),
            "random": random_str,
            "reqData": reqData_str
        }

        sign = cls.create_sign(params)

        postData_json = {
            "random": random_str,
            "sign": sign,
            "timestamp": timestamp,
            "reqData": reqData_str
        }
        postData_str = json.dumps(postData_json, ensure_ascii=False, indent=None, separators=(',', ':'))
        return {"url": url, "data": postData_str}

    @classmethod
    # 获取设备控制日志（https）
    def get_device_loglist(cls, user_id, family_id, device_id):
        url = FETCH_LOG_URL
        postData_json = {
            "size": 20,
            "type": 0,
            "nextId": "",
            "familyId": family_id,
            "userId": user_id,
            "language": "zh",
            "deviceId": device_id
        }
        postData_str = json.dumps(postData_json, ensure_ascii=False, indent=None, separators=(',', ':'))

        return {"url": url, "data": postData_str}

    @classmethod
    # 通过用户名和密码登录服务器获取access_token和userId（https）
    def get_access_token_by_password(cls, username: str, password: str):
        url = f"https://{HTTPS_HOST}/getOauthToken?userName={username}&type=0&password={password}"
        return {"url": url, "data": None}

    @classmethod
    # 通过sessionId获取access_token和userId（https）
    def get_access_token_by_session_id(cls, session_id):
        url = f"https://{HTTPS_HOST}/getOauthToken?type=0&sessionId={session_id}"
        posr_data = f"type: '0'\nsessionId: {session_id}"
        return {"url": url, "data": posr_data}

    @classmethod
    # 查询家庭成员统计信息: familyId和familyName（https）
    def get_family_statistics_users(cls, user_id, access_token):
        url = f"https://{HTTPS_HOST}/v2/family/statistics/users"

        timestamp = generate_timestamp()
        random_str = generate_uuid()
        req_data = {
            "accessToken": access_token,
            "random": random_str,
            "userId": user_id,
            "sign": "1234567890",
            "timestamp": timestamp,
            "requestId": generate_uuid()
        }
        params = {
            "requestId": req_data["requestId"],
            "userId": req_data["userId"],
            "accessToken": req_data["accessToken"],
            "random": req_data["random"],
            "timestamp": req_data["timestamp"]
        }

        sign = cls.create_sign(params)
        req_data["sign"] = sign
        postData_str = json.dumps(req_data, ensure_ascii=False, indent=None)
        return {"url": url, "data": postData_str}

    @classmethod
    # 获取开关设备状态信息？（https）
    def get_devices_status(cls, access_token, session_id, user_id, user_name, family_id):
        url = f"https://{HTTPS_HOST}/v2/cmd/app/readtable"

        random_str = generate_uuid()
        serial = generate_serial()
        timestamp = generate_timestamp()

        lastUpdateTime = int(generate_timestamp() / 1000) - 30000
        lastUpdateTime = 1761670123

        req_data = {
            "accessToken": access_token,
            "random": random_str,
            "serial": serial,
            "userId": user_id,
            "userName": user_name,
            "lastUpdateTime": lastUpdateTime,
            "ver": SOFTWARE_VER,
            "sign": "1234567890",
            "timestamp": timestamp,
            "sessionId": session_id,
            "deviceFlag": 0,
            "familyId": family_id,
            "pageIndex": 0,
            "dataType": "all"
        }
        #参数加密前排序
        params = {
            "accessToken": req_data["accessToken"],
            "dataType": req_data["dataType"],
            "deviceFlag": req_data["deviceFlag"],
            "familyId": req_data["familyId"],
            "lastUpdateTime": req_data["lastUpdateTime"],
            "pageIndex": req_data["pageIndex"],
            "random": req_data["random"],
            "sessionId": req_data["sessionId"],
            "serial": req_data["serial"],
            "timestamp": str(timestamp),
            "userId": req_data["userId"],
            "userName": req_data["userName"],
            "ver": req_data["ver"]
        }

        sign = cls.create_sign(params)
        req_data["sign"] = sign
        postData_str = json.dumps(req_data, ensure_ascii=False, indent=None)

        return {"url": url, "data": postData_str}

    @classmethod
    # 查询首页信息 （全数据）（https）
    def get_homepage_data(cls, family_id, user_id, access_token):
        url = f"https://{HTTPS_HOST}/v2/family/config/queryHomepageData"

        timestamp = generate_timestamp()
        random_str = generate_uuid()
        req_data = {
            "accessToken": access_token,
            "random": random_str,
            "userId": user_id,
            "familyId": family_id,
            "sign": "1234567890",
            "timestamp": timestamp,
            "requestId": generate_uuid()
        }
        params = {
            "requestId": req_data["requestId"],
            "userId": req_data["userId"],
            "accessToken": req_data["accessToken"],
            "familyId": req_data["familyId"],
            "random": req_data["random"],
            "timestamp": req_data["timestamp"]
        }

        sign = cls.create_sign(params)
        req_data["sign"] = sign
        postData_str = json.dumps(req_data, ensure_ascii=False, indent=None)

        return {"url": url, "data": postData_str}

def post_request(url, post_data):
    session = requests.Session()
    req = requests.Request(
        method="POST",
        url=url,
        data=post_data,
        headers=HTTP_HEADERS  # 仅添加必要头
    )
    prepared_req = session.prepare_request(req)
    if "Accept" in prepared_req.headers:
        del prepared_req.headers["Accept"]  # 删除 "Accept: */*"
    if "Connection" in prepared_req.headers:
        del prepared_req.headers["Connection"]  # 删除 "Connection: keep-alive"
    if proxies:
        resp = session.send(prepared_req, proxies=proxies, verify=False)
    else:
        resp = session.send(prepared_req, verify=False)
    resp_json= json.loads(resp.text)

    if resp.status_code == 200:
        return resp_json
    else:
        return resp_json

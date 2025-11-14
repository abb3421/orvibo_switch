# 协议命令
# from pyotgw.vars import MSG_TSP
# from scapy.contrib.automotive.ccp import UPLOAD_DTO
from datetime import timedelta

# 通过HTTPS请求进行设备状态更新的频率（默认30秒）
UPDATE_INTERVAL = timedelta(seconds=60)
# SSL自动重连的时间间隔（单位：秒），空闲400秒后服务器会主动断开
SSL_RECONNECT_INTERVAL = 0
# 重连最大重连尝试次数（达到后放弃）
SSL_MAX_RECONNECT_ATTEMPTS = 3

CMD_HELLO = 0
CMD_LOGIN = 2
CMD_CONTROL = 15
CMD_STATE_UPDATE = 42
CMD_HEARTBEAT = 32
CMD_HANDSHAKE = 6

#终端设备信息
SOFTWARE_NAME = "ZhiJia365"
SOFTWARE_VERSION = "50104302"
SYS_VERSION = "Android11_30"
HARDWARE_VERSION = "Nexus 5"
LANGUAGE = "en" #en
PHONE_NAME = "Android Bluedroid"
SOFTWARE_VER = "5.1.4.302"
DEBUG_INFO = "Android_ZhiJia365_30_5.1.4.302"

# 平台
PLATFORM_SWITCH = "switch"
DOMAIN = "orvibo_switch"
#厂商信息
MANUFACTURER = "欧瑞博"
DEVICE_NAME = "Orvibo Switch"
DEVICE_TYPE = "orvibo_switch"
# 支持的产品
ORVIBO_SWITCH_MODEL = {
    "56d124ba95474fc98aafdb830e933789": "S20c",
    "04aa419575be4714a853a82be3f22035": "S30c",
}

#HTTPS通讯
LOGIN_URL = "https://homemate.orvibo.com/getOauthToken"
UPLOAD_LOG_URL = "https://log-upload-cn.orvibo.com/data/upload"
FETCH_LOG_URL = "https://homemate-uselog.orvibo.com/ctrlLog/device/loglist"
HTTPS_HOST = "china.orvibo.com"
#HTTPS_HOST = "homemate.orvibo.com"
HTTP_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "User-Agent": "okhttp/3.12.8",
}
#HTTPS请求包签名密钥
SIGN_KEY = "nQ45RjPtOws96jmH"

#SSL通讯
SSL_HOST = "china.orvibo.com"
#SSL_HOST = "homemate.orvibo.com"
SSL_PORT = 10002
SOCKET_TIMEOUT = 10
CLIENT_CERT = "./certs/client_cert.pem"
CLIENT_KEY = "./certs/client_key.pem"
SERVER_CA = "./certs/server_ca.pem"
#SSL数据包默认加密密钥
DEFAULT_KEY = "khggd54865SNJHGF"
#SSL数据包标识
MAGIC = bytes([0x68, 0x64])
#默认会话ID（空）
ID_UNSET = b'\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20'






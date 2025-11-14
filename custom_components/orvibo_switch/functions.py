# custom_components/wifi_switch/functions.py
import time
import random
import uuid
import hmac
import hashlib
import json

def text_utils_is_empty(s):
    """精确模拟Android的TextUtils.isEmpty()方法"""
    if s is None:
        return True
    if not isinstance(s, str):
        return False
    return len(s) == 0

def generate_serial(use_time: bool = False):
    if use_time:
        return int(time.time() * 1000)
    else:
        return random.randint(1, 2147483647)

def generate_timestamp():
    """生成当前毫秒级时间戳（与Java System.currentTimeMillis()一致）"""
    return int(time.time() * 1000)

def generate_uuid(remove_hyphen: bool = True) -> str:
    uuid_str = str(uuid.uuid4())
    # 根据参数决定是否过滤 '-'
    if remove_hyphen:
        return uuid_str.replace("-", "")
    return uuid_str

def hmac_sha256(key, data):
    # 创建HMAC SHA256实例
    h = hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)

    # 计算HMAC并转换为十六进制字符串（模拟Java代码中的字节到十六进制转换）
    # Java代码中使用了自定义的十六进制编码，这里保持一致
    hex_digits = '0123456789abcdef'
    digest = h.digest()
    result = []
    for b in digest:
        # 与Java代码中的逻辑完全对应：(b & 255) 确保为无符号字节
        i = b & 0xff
        # 高4位和低4位分别转换
        result.append(hex_digits[i >> 4])
        result.append(hex_digits[i & 0x0f])

    # 转为大写并返回
    return ''.join(result).upper()

def print_formatted_json(data, indent=2, ensure_ascii=False):
    """
    格式化打印JSON数据

    参数:
        data: 要打印的JSON数据（可以是字典、列表等Python对象，或JSON字符串）
        indent: 缩进空格数，默认2
        ensure_ascii: 是否保证ASCII编码，False则保留中文等非ASCII字符
    """
    try:
        # 如果输入是字符串，先解析为Python对象
        if isinstance(data, str):
            data = json.loads(data)

        # 格式化并打印
        formatted_json = json.dumps(
            data,
            indent=indent,
            ensure_ascii=ensure_ascii,
            sort_keys=False  # 不排序键，保持原顺序
        )
        print(formatted_json)
    except json.JSONDecodeError:
        print("错误：输入的字符串不是有效的JSON格式")
    except Exception as e:
        print(f"格式化JSON时发生错误：{str(e)}")


def format_mac(mac):
    # 先去除可能存在的非十六进制字符（可选，确保输入纯净）
    mac = ''.join(filter(str.isalnum, mac)).lower()
    if len(mac) != 12:
        raise ValueError("MAC地址必须是12位十六进制字符")
    # 每2个字符分组，用冒号连接
    return ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
# custom_components/wifi_switch/config_flow.py
import logging
import hashlib
import json
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
import aiohttp
from .const import(
    DOMAIN,
    LOGIN_URL
)

_LOGGER = logging.getLogger(__name__)

# 表单配置（不变，用户仍输入明文密码）
STEP_USER_DATA_SCHEMA = vol.Schema({
    vol.Required("username", description={"suggested_value": ""}): str,
    vol.Required("password"): vol.All(str, vol.Length(min=1)),
})


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    async def async_step_user(
            self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        if user_input is None:
            return self.async_show_form(
                step_id="user",
                data_schema=STEP_USER_DATA_SCHEMA,
                description_placeholders={
                    "title": "配置我的自定义集成",
                    "username": "请输入账号",
                    "password": "请输入密码"
                }
            )

        errors = {}
        user_id = ""
        md5_password = self._get_md5_hash(user_input["password"])
        try:
            # 调用校验方法（内部会将密码转MD5并发起GET请求）
            user_id = await self._async_validate_credentials(
                username=user_input["username"],
                password=md5_password,
                server_url=LOGIN_URL
            )
        except ValueError:
            # 账号密码错误（服务器返回无效）
            errors["base"] = "invalid_auth"
            _LOGGER.error("invalid_auth")
        except aiohttp.ClientError:
            # 网络错误（连接超时、无法访问等）
            errors["base"] = "connection_failed"
            _LOGGER.error("connection_failed")
        except Exception as e:
            # 其他未知错误
            errors["base"] = "unknown_error"
            _LOGGER.error(f"unknown_error：{str(e)}")

        if errors:
            return self.async_show_form(
                step_id="user",
                data_schema=STEP_USER_DATA_SCHEMA,
                errors=errors
            )

        # 校验通过：存储明文密码？No！存储 MD5 后的密码（后续请求直接用）
        # 注意：这里建议存储 MD5 后的密码，避免后续重复加密
        final_data = {
            "userName": user_input["username"],
            "passWord": md5_password,  # 存储 MD5 密码，而非明文
            "userId": user_id
        }

        return self.async_create_entry(
            title=f"Orvibo：{user_id}",
            data=final_data  # 存储用户名 + MD5密码（HA自动加密）
        )

    @staticmethod
    def _get_md5_hash(password: str) -> str:
        """将明文密码转为 MD5 32 位小写字符串（通用格式）"""
        # 注意：编码必须为 UTF-8（与服务器一致，避免中文/特殊字符加密不一致）
        md5_obj = hashlib.md5(password.encode("utf-8"))
        return md5_obj.hexdigest().upper() # 返回 32 位大写字符串

    async def _async_validate_credentials(self, username: str, password: str, server_url: str):
        """
        异步校验账号密码：
        1. 发起 GET 请求（携带用户名 + MD5密码）；
        2. 验证服务器返回结果。
        """
        # 构造 GET 请求参数（query params）
        params = {
            "userName": username,
            "password": password  # 传递 MD5 后的密码
        }

        # 发起异步 GET 请求（aiohttp.ClientSession 是 HA 推荐的异步请求方式）
        async with aiohttp.ClientSession() as session:
            async with session.get(
                    url=server_url,
                    params=params,  # 自动将 params 拼接到 URL（如 ?username=xxx&password=md5xxx）
                    timeout=aiohttp.ClientTimeout(total=10)  # 10秒超时（避免无限等待）
            ) as response:
                # 1. 先判断响应状态码（200 = 成功）
                if response.status != 200:
                    raise ValueError("服务器返回无效状态")

                # 2. 解析响应数据（根据服务器返回格式调整，这里假设返回 JSON）
                response_data = await response.text()
                response_json = json.loads(response_data)

                # 3. 根据服务器返回判断是否登录成功（示例逻辑，需与服务器约定）
                # 假设服务器返回 {"code": 0, "msg": "success"} 表示成功
                if response_json.get("status") != 0 or response_json .get("data") is None:
                    raise ValueError(f"登录失败：{response_json .get('message', '未知错误1')}")
                if response_json.get("data",{}).get("access_token","") is None:
                    raise ValueError(f"登录失败：{response_json.get('message', '未知错误2')}")
                return response_json.get("data",{}).get("user_id","")

# --- Realistic Unique Device System যুক্ত করা হয়েছে ---
# Feature:
#   1) reset_all_devices() → সব device profile + cookies ডিলিট করবে
#   2) create_new_device(user_tag) → প্রতিবার নতুন realistic device বানাবে
#   3) মেনুর Reset এবং Set User Agent বাটনের সাথে bind করা হয়েছে

import os
import re
import json
import uuid
import shutil
import random
import hashlib
import hmac
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, Optional, List, Tuple
from http.cookiejar import MozillaCookieJar
import aiohttp
import aiofiles
import asyncio
from datetime import datetime, timezone, timedelta
import logging
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler
from telegram.error import NetworkError, BadRequest
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
import base64
import socket
import requests
import pytz
from flask import Flask, request, jsonify
import threading
import subprocess

# ---------- Flask Setup ----------
app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({"status": "Bot is running", "timestamp": format_bd_time()})

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "time": format_bd_time()})

def run_flask():
    """Run Flask in a separate thread to avoid port conflicts"""
    try:
        # Try different ports if 5000 is busy
        for port in [5000, 5001, 5002, 5003]:
            try:
                app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
                break
            except OSError as e:
                if "Address in use" in str(e):
                    continue
                raise
    except Exception as e:
        logger.error(f"Flask server error: {str(e)}")

# ---------- Utilities ----------
def _luhn_checksum(number: str) -> int:
    def digits_of(n): return [int(d) for d in n]
    digits = digits_of(number)
    odd = digits[-1::-2]
    even = digits[-2::-2]
    total = sum(odd)
    for d in even:
        d2 = d * 2
        total += d2 if d2 < 10 else d2 - 9
    return total % 10

def generate_imei(seed: str) -> str:
    tacs = ["358240", "352099", "356938", "353918", "357805", "355031", "354859"]
    tac = random.Random(seed).choice(tacs)
    rnd = random.Random(seed + "imei")
    snr = "".join(str(rnd.randrange(0, 10)) for _ in range(8))
    partial = tac + snr
    checksum = _luhn_checksum(partial + "0")
    check_digit = (10 - checksum) % 10
    return partial + str(check_digit)

def generate_android_id(seed: str) -> str:
    rnd = random.Random(seed + "android")
    return "".join(rnd.choice("0123456789abcdef") for _ in range(16))

def generate_mac(seed: str) -> str:
    rnd = random.Random(seed + "mac")
    first = rnd.randrange(0, 256) | 0b00000010
    mac_bytes = [first] + [rnd.randrange(0, 256) for _ in range(5)]
    return ":".join(f"{b:02X}" for b in mac_bytes)

def generate_device_seed(name: str) -> str:
    base = f"{name}::{uuid.uuid5(uuid.NAMESPACE_DNS, name)}"
    return hashlib.sha256(base.encode()).hexdigest()

def stable_hash(seed: str, *parts: str, length: int = 32) -> str:
    msg = "||".join(parts)
    h = hmac.new(seed.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return h[:length]

def random_hex(length):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

def get_bd_timezone_locale():
    tz = "Asia/Dhaka"
    tz_offset = int(datetime.now(pytz.timezone(tz)).utcoffset().total_seconds()/3600)
    locale = "bn_BD"
    language = "bn"
    return tz, tz_offset, locale, language

def get_bd_time():
    """Bangladesh time return করে"""
    bd_tz = pytz.timezone('Asia/Dhaka')
    return datetime.now(bd_tz)

def format_bd_time(dt=None):
    """Bangladesh time format করে"""
    if dt is None:
        dt = get_bd_time()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def get_device_network_info():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"

    try:
        r = requests.get("https://ipinfo.io/json").json()
        public_ip = r.get("ip", local_ip)
        isp = r.get("org", "Unknown ISP")
        asn = r.get("asn", "Unknown ASN")
        hostname = r.get("hostname", socket.gethostname())
    except:
        public_ip = local_ip
        isp = "Unknown ISP"
        asn = "Unknown ASN"
        hostname = socket.gethostname()

    return {
        "local_ip": local_ip,
        "public_ip": public_ip,
        "hostname": hostname,
        "isp": isp,
        "asn": asn,
        "proxy": None,
        "type": "real_device"
    }

def generate_behavior():
    return {
        "typing_speed_ms": random.randint(80,250),
        "click_delay_ms": random.randint(100,500),
        "scroll_speed_px": random.randint(200,1000)
    }

def generate_installed_apps():
    common_apps = ["WhatsApp", "Gmail", "YouTube", "Chrome", "Facebook", "Instagram", "Camera"]
    return random.sample(common_apps, random.randint(3, len(common_apps)))

@dataclass
class DeviceProfile:
    name: str
    seed: str
    device_id: str
    android_id: str
    imei: str
    mac_wifi: str
    ua: str
    canvas_fp: str
    audio_fp: str
    battery: Dict[str, Any]
    screen: Dict[str, Any]
    sensors: List[str]
    installed_apps: List[str]
    storage: Dict[str, Any]
    timezone: str
    utc_offset_hours: float
    locale: str
    language: str
    network: Dict[str, Any]
    behavior: Dict[str, Any]
    created_at: str
    proxy: Optional[Dict[str, str]] = None  # নতুন ফিল্ড: প্রক্সি তথ্য

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "DeviceProfile":
        return DeviceProfile(**d)

# ---------- Manager ----------
class DeviceProfileManager:
    def __init__(self, base_dir: str = "devices"):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def _profile_path(self, name: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_\-\.]+", "_", name)
        return os.path.join(self.base_dir, f"{safe}.json")

    def _cookie_path(self, name: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_\-\.]+", "_", name)
        return os.path.join(self.base_dir, f"{safe}.cookies.txt")

    def exists(self, name: str) -> bool:
        return os.path.exists(self._profile_path(name))

    def load(self, name: str) -> DeviceProfile:
        with open(self._profile_path(name), "r", encoding="utf-8") as f:
            data = json.load(f)
        return DeviceProfile.from_dict(data)

    def save(self, profile: DeviceProfile) -> None:
        with open(self._profile_path(profile.name), "w", encoding="utf-8") as f:
            json.dump(profile.to_dict(), f, ensure_ascii=False, indent=2)

    async def create(self, name: str) -> DeviceProfile:
        seed = generate_device_seed(name + str(uuid.uuid4()))
        tz, tz_offset, locale, language = get_bd_timezone_locale()
        net_info = get_device_network_info()

        used_devices = load_used_devices()
        while True:
            device_id = stable_hash(seed, "device", length=32)
            if device_id not in used_devices:
                break
            seed = generate_device_seed(name + str(uuid.uuid4()))

        user_agents = await load_user_agents_from_file()
        if not user_agents:
            user_agents = ANDROID_UAS
        ua = random.choice(user_agents)

        profile = DeviceProfile(
            name=name,
            seed=seed,
            device_id=device_id,
            android_id=generate_android_id(seed),
            imei=generate_imei(seed),
            mac_wifi=generate_mac(seed),
            ua=ua,
            canvas_fp=stable_hash(seed, ua, "canvas", length=40),
            audio_fp=stable_hash(seed, ua, "audio", length=40),
            battery={
                "level": random.randint(20,100),
                "charging": random.choice([True, False])
            },
            screen={
                "width": random.choice([1080, 1440, 1600, 2160]),
                "height": random.choice([1920, 2340, 3200, 3840]),
                "density": random.choice([2.5, 3, 3.5])
            },
            sensors=random.sample(["accelerometer", "gyroscope", "magnetometer", "light", "proximity"], random.randint(3,5)),
            installed_apps=generate_installed_apps(),
            storage={},
            timezone=tz,
            utc_offset_hours=tz_offset,
            locale=locale,
            language=language,
            network=net_info,
            behavior=generate_behavior(),
            created_at=format_bd_time()
        )
        await save_used_device(device_id)
        self.save(profile)
        cj = MozillaCookieJar(self._cookie_path(name))
        cj.save(ignore_discard=True, ignore_expires=True)
        return profile

    def reset_all(self):
        if os.path.exists(self.base_dir):
            shutil.rmtree(self.base_dir)
        os.makedirs(self.base_dir, exist_ok=True)
        # used_devices.json ডিলিট করা হবে না

    async def create_new_device(self, user_tag: str) -> DeviceProfile:
        return await self.create(user_tag)

    async def set_proxy(self, name: str, proxy_string: str) -> bool:
        proxy = parse_proxy_string(proxy_string)
        if not proxy:
            return False
        profile = self.load(name)
        profile.proxy = proxy
        self.save(profile)
        logger.info(f"Proxy set for device {name}: {proxy['host']}:{proxy['port']}")
        return True

    async def auto_set_proxy(self, name: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Automatically select and set a proxy from proxies.txt for the given device profile.
        Returns (success, proxy_info, message).
        """
        proxy_string = await select_random_proxy()
        if not proxy_string:
            return False, None, "No valid proxies found in proxies.txt."
        
        success = await self.set_proxy(name, proxy_string)
        if not success:
            return False, None, "Invalid proxy format in proxies.txt."
        
        profile = self.load(name)
        proxy_info = await fetch_proxy_info(profile.proxy)
        if not proxy_info.get("success"):
            return False, None, f"Failed to connect to proxy: {proxy_info.get('error')}"
        
        logger.info(f"Automatically set proxy for device {name}: {proxy_string}")
        return True, proxy_info, "Proxy set successfully!"

    async def build_session(self, name: str) -> aiohttp.ClientSession:
        profile = self.load(name)
        headers = {
            "User-Agent": profile.ua,
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "X-Device-ID": profile.device_id,
            "X-Android-ID": profile.android_id,
            "X-IMEI": profile.imei,
            "X-Canvas-FP": profile.canvas_fp,
            "X-Audio-FP": profile.audio_fp,
            "sec-ch-ua-platform": '"Android"',
            "sec-ch-ua": '"Chromium";v="142", "Android WebView";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?1",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "priority": "u=1, i"
        }
        
        if profile.proxy:
            proxy_url = f"http://{profile.proxy['username']}:{profile.proxy['password']}@{profile.proxy['host']}:{profile.proxy['port']}"
            session = aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=False), proxy=proxy_url)
        else:
            session = aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=False))
        return session

def parse_proxy_string(proxy_string: str) -> Optional[Dict[str, str]]:
    try:
        parts = proxy_string.split(':')
        if len(parts) != 4:
            raise ValueError("Invalid proxy format. Expected format: host:port:username:password")
        host, port, username, password = parts
        if not host or not port.isdigit() or not username or not password:
            raise ValueError("Invalid proxy components")
        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password
        }
    except Exception as e:
        logger.error(f"Error parsing proxy string: {str(e)}")
        return None

async def fetch_proxy_info(proxy: Dict[str, str]) -> Dict[str, Any]:
    try:
        proxy_url = f"http://{proxy['username']}:{proxy['password']}@{proxy['host']}:{proxy['port']}"
        async with aiohttp.ClientSession() as session:
            async with session.get("https://ipinfo.io/json", proxy=proxy_url, timeout=10) as response:
                if response.status != 200:
                    return {"success": False, "error": f"HTTP {response.status}"}
                data = await response.json()
                return {
                    "success": True,
                    "public_ip": data.get("ip", "Unknown"),
                    "location": {
                        "country": data.get("country", "Unknown"),
                        "region": data.get("region", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "zip_code": data.get("postal", "Unknown"),
                        "latitude": data.get("loc", "").split(",")[0] if data.get("loc") else "Unknown",
                        "longitude": data.get("loc", "").split(",")[1] if data.get("loc") else "Unknown",
                        "timezone": data.get("timezone", "Unknown")
                    },
                    "network": {
                        "isp": data.get("org", "Unknown"),
                        "organization": data.get("org", "Unknown"),
                        "as_number": data.get("asn", "Unknown"),
                        "proxy_vpn": data.get("vpn", False),
                        "hosting": data.get("hosting", False)
                    }
                }
    except Exception as e:
        logger.error(f"Error fetching proxy info: {str(e)}")
        return {"success": False, "error": str(e)}

async def load_proxies_from_file():
    proxy_file = "proxies.txt"
    proxies = []
    try:
        async with aiofiles.open(proxy_file, 'r') as f:
            async for line in f:
                proxy_string = line.strip()
                if proxy_string and parse_proxy_string(proxy_string):
                    proxies.append(proxy_string)
        logger.info(f"Loaded {len(proxies)} valid proxies from {proxy_file}")
        return proxies
    except Exception as e:
        logger.error(f"Error loading proxies from {proxy_file}: {str(e)}")
        return []

async def select_random_proxy():
    proxies = await load_proxies_from_file()
    if not proxies:
        return None
    return random.choice(proxies)

# Constants
KEY = b'djchdnfkxnjhgvuy'
IV = b'ayghjuiklobghfrt'
TELEGRAM_TOKEN = "8445698549:AAGcT3wyGecDs3Nbs4UFbjViIABOA5NYw9s"
ADMIN_ID = 5624278091
TOKEN_FILE = "tokens.json"
USER_STATUS_FILE = "user_status.json"
USER_AGENTS_FILE = "user_agents.json"  # Legacy
USED_USER_AGENTS_FILE = "used_user_agents.json"  # Legacy
DEVICE_HISTORY_FILE = "device_history.json"  # Legacy
REQUEST_TIMEOUT = 8
MAX_RETRIES = 3
MAX_CODE_ATTEMPTS = 10
CODE_CHECK_INTERVAL = 2
REGISTRATION_FILE = "registration_data.txt"
ANDROID_UAS = [
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Xiaomi 14 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-N986B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; OnePlus 11R) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-F731B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Moto G84) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
]

# Website configurations - DIY website added with new endpoints
WEBSITE_CONFIGS = {
    "DIY": {
        "name": "DIY",
        "api_domain": "https://diy22.club/",
        "origin": "https://diy22.com",
        "referer": "https://diy22.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://diy22.club/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://diy22.club/api/task_stat/wsServer",
        "bulk_send_url": "https://diy22.vip/api/ws_send/send"
    },
    "TASKS": {
        "name": "TASKS",
        "api_domain": "https://task33.club/",
        "origin": "https://task33.com",
        "referer": "https://task33.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://task33.club/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://task33.club/api/task_stat/wsServer",
        "bulk_send_url": "https://task33.vip/api/ws_send/send"
    },
    "JOB": {
        "name": "JOB",
        "api_domain": "https://job777.club/",
        "origin": "https://job777.me",
        "referer": "https://job777.me/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://job777.club/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://job777.club/api/task_stat/wsServer",
        "bulk_send_url": "https://job777.vip/api/ws_send/send"
    },
    "TG": {
        "name": "TG",
        "api_domain": "https://tg299.online/",
        "origin": "https://tg299.club",
        "referer": "https://tg299.club/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://tg299.online/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://tg299.online/api/task_stat/wsServer",
        "bulk_send_url": "https://tg299.vip/api/ws_send/send"
    },
    "NEWS": {
        "name": "NEWS",
        "api_domain": "https://mess6.club/",
        "origin": "https://news669.com",
        "referer": "https://news669.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://mess6.club/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://mess6.club/api/task_stat/wsServer",
        "bulk_send_url": "https://mess6.vip/api/ws_send/send"
    },
    "SMS": {
        "name": "SMS",
        "api_domain": "https://sms323.club/",
        "origin": "https://sms323.com",
        "referer": "https://sms323.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://sms323.club/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://sms323.club/api/task_stat/wsServer",
        "bulk_send_url": "https://sms323.vip/api/ws_send/send"
    },
    "OK": {
        "name": "OK",
        "api_domain": "https://ok8job.cc/",
        "origin": "https://www.ok8job.net",
        "referer": "https://www.ok8job.net/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://ok8job.cc/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://ok8job.cc/api/task_stat/wsServer",
        "bulk_send_url": "https://ok8job.cloud/api/ws_send/send"
    },
    "W8": {
        "name": "W8",
        "api_domain": "https://w8job.cyou/",
        "origin": "https://w8job.club",
        "referer": "https://w8job.club/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://w8job.cyou/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://w8job.cyou/api/task_stat/wsServer",
        "bulk_send_url": "https://w8job.vip/api/ws_send/send"
    },
     "DEP": {
        "name": "DEP",
        "api_domain": "https://dep6.club/",
        "origin": "https://dep6.com",
        "referer": "https://dep6.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://dep6.club/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://dep6.club/api/task_stat/wsServer",
        "bulk_send_url": "https://dep6.vip/api/ws_send/send"
    },
    "ATM": {
        "name": "ATM",
        "api_domain": "https://atm001.com/",
        "origin": "http://atm8.me",
        "referer": "http://atm8.me/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://atm001.com/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://atm001.com/api/task_stat/wsServer",
        "bulk_send_url": "https://atm001.vip/api/ws_send/send"
    },
    "MK": {
        "name": "MK",
        "api_domain": "https://mk8ht.com/",
        "origin": "http://mmmmm.cyou",
        "referer": "http://mmmmm.cyou/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://mk8ht.com/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://mk8ht.com/api/task_stat/wsServer",
        "bulk_send_url": "https://mk8ht.vip/api/ws_send/send"
    },
    "22JOB": {
        "name": "22JOB",
        "api_domain": "https://web.112233job.com/",
        "origin": "https://22job.me",
        "referer": "https://22job.me/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://web.112233job.com/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://web.112233job.com/api/task_stat/wsServer",
        "bulk_send_url": "https://22job.vip/api/ws_send/send"
    },
    "WA": {
        "name": "WA",
        "api_domain": "https://web.wa2.club/",
        "origin": "http://wa2.club",
        "referer": "http://wa2.club/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/user_ws/sendCode",
        "get_code_path": "api/user_ws/getCode",
        "phone_list_url": "https://web.wa2.club/api/user_ws/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code",
        "task_stat_url": "https://web.wa2.club/api/task_stat/wsServer",
        "bulk_send_url": "https://wa2.vip/api/ws_send/send"
    },
    "AMZN": {
        "name": "AMZ",
        "api_domain": "https://web.amznvip.com/",
        "origin": "https://amznvip.com",
        "referer": "https://amznvip.com/",
        "login_path": "api/user/login",
        "send_code_path": "api/task/send_code",
        "get_code_path": "api/task/get_code",
        "phone_list_url": "https://web.amznvip.com/api/task/phone_list",
        "signup_path": "api/user/register",
        "referral_field": "invitation",
        "task_stat_url": "https://web.amznvip.com/api/task_stat/wsServer",
        "bulk_send_url": "https://amznvip.vip/api/ws_send/send"
    }
}

# Fixed headers for consistency
ACCEPT_LANGUAGE = "en-US,en;q=0.9"
SEC_CH_UA_PLATFORM = '"Android"'
SEC_CH_UA_LIST = [
    '"Not)A;Brand";v="99", "Chromium";v="113", "Google Chrome";v="113"',
    '"Not)A;Brand";v="24", "Chromium";v="119", "UCBrowser";v="16.8"',
    '"Not)A;Brand";v="8", "Chromium";v="111", "Google Chrome";v="111"',
]
SEC_CH_UA_MOBILE = "?1"
DEFAULT_SELECTED_WEBSITE = "DIY"

# Randomization for headers to reduce fingerprinting
def get_random_accept_encoding():
    encodings = [
        "gzip, deflate",
        "gzip, deflate, br",
        "gzip, deflate, br, zstd",
        "deflate, br"
    ]
    return random.choice(encodings)

def get_random_sec_fetch_headers():
    sites = ["none", "same-origin", "same-site", "cross-site"]
    modes = ["cors", "navigate", "no-cors"]
    dests = ["empty", "document", "object"]
    return {
        "sec-fetch-site": random.choice(sites),
        "sec-fetch-mode": random.choice(modes),
        "sec-fetch-dest": random.choice(dests)
    }

def get_random_priority():
    priorities = ["u=0", "u=1", "u=1, i"]
    return random.choice(priorities)

# Custom logging filter to mask sensitive data
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'msg'):
            record.msg = re.sub(r'\+\d{11,12}', '****MASKED_PHONE****', record.msg)
            record.msg = re.sub(r'(?<=token: )[\w-]{10}[\w-]+', lambda m: m.group(0)[:10] + '...', record.msg)
            record.msg = re.sub(r'(?<=password: )[\w@.-]+', '****MASKED_PASSWORD****', record.msg)
            record.msg = re.sub(r'(?<=username: )[\w@.-]+', '****MASKED_USERNAME****', record.msg)
        return True

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.addFilter(SensitiveDataFilter())

token_cache = {}
user_status_cache = {"approved": [], "blocked": []}
cache_loaded = False

device_manager = DeviceProfileManager()

async def load_user_agents_from_file():
    ua_file = "ua_agents.txt"
    user_agents = []
    try:
        async with aiofiles.open(ua_file, 'r') as f:
            async for line in f:
                # অতিরিক্ত টেক্সট (যেমন, নম্বর বা ডট) রিমুভ করা
                agent = re.sub(r'^\d+\.\s*|\s*$', '', line.strip())
                if agent and detect_platform_from_user_agent(agent) in ['android', 'default']:
                    user_agents.append(agent)
        logger.info(f"Loaded {len(user_agents)} valid Android User Agents from {ua_file}")
        return user_agents
    except Exception as e:
        logger.error(f"Error loading User Agents from {ua_file}: {str(e)}")
        return []

USED_DEVICES_FILE = "used_devices.json"

def load_used_devices():
    try:
        if os.path.exists(USED_DEVICES_FILE):
            with open(USED_DEVICES_FILE, 'r') as f:
                return set(json.load(f))
        return set()
    except Exception as e:
        logger.error(f"Error loading used devices: {str(e)}")
        return set()

async def save_used_device(device_id):
    used = load_used_devices()
    used.add(device_id)
    async with aiofiles.open(USED_DEVICES_FILE, 'w') as f:
        await f.write(json.dumps(list(used), indent=4))

def detect_platform_from_user_agent(user_agent):
    user_agent_lower = user_agent.lower()
    if 'android' in user_agent_lower:
        return 'android'
    elif 'windows' in user_agent_lower:
        return 'windows'
    elif 'iphone' in user_agent_lower or 'ipad' in user_agent_lower:
        return 'ios'
    elif 'mac os' in user_agent_lower or 'macintosh' in user_agent_lower:
        return 'macos'
    elif 'linux' in user_agent_lower:
        return 'linux'
    else:
        return 'default'

def get_main_keyboard(selected_website=DEFAULT_SELECTED_WEBSITE, user_id=None):
    link_text = f"Link {selected_website} WhatsApp"
    number_list_text = f"{selected_website} Number List"
    device_set = device_manager.exists(str(user_id))
    set_user_agent_text = f"{'✅ ' if device_set else ''}Set User Agent"
    proxy_set = device_set and device_manager.load(str(user_id)).proxy is not None
    set_proxy_text = f"{'✅ ' if proxy_set else ''}Set Proxy"
    keyboard = [
        [KeyboardButton("Log in Account"), KeyboardButton("Register Account")],
        [KeyboardButton(link_text), KeyboardButton(number_list_text)],
        [KeyboardButton("Task Statistics"), KeyboardButton("Bulk Send")],
        [KeyboardButton("Reset All"), KeyboardButton(set_user_agent_text)],
        [KeyboardButton(set_proxy_text), KeyboardButton("Manual Proxy")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=False)

def get_website_selection_keyboard():
    # WEBSITE_CONFIGS থেকে সব ওয়েবসাইটের নাম নেওয়া
    websites = list(WEBSITE_CONFIGS.keys())
    # দুটি করে বাটন এক সারিতে রাখার জন্য
    keyboard = []
    for i in range(0, len(websites), 2):
        row = [KeyboardButton(websites[i])]
        if i + 1 < len(websites):
            row.append(KeyboardButton(websites[i + 1]))
        keyboard.append(row)
    # Back to Main Menu বাটন যুক্ত করা
    keyboard.append([KeyboardButton("Back to Main Menu")])
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)

def get_confirmation_keyboard():
    keyboard = [
        [KeyboardButton("Yes"), KeyboardButton("No")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)

def load_user_status():
    global user_status_cache, cache_loaded
    if not cache_loaded:
        try:
            if os.path.exists(USER_STATUS_FILE):
                with open(USER_STATUS_FILE, 'r') as f:
                    user_status_cache = json.load(f)
            cache_loaded = True
        except Exception as e:
            logger.error(f"Error loading user status: {str(e)}")
    return user_status_cache

async def save_user_status(status):
    global user_status_cache
    try:
        user_status_cache = status
        async with aiofiles.open(USER_STATUS_FILE, 'w') as f:
            await f.write(json.dumps(status, indent=4))
    except Exception as e:
        logger.error(f"Error saving user status: {str(e)}")

def load_tokens():
    global token_cache, cache_loaded
    if not cache_loaded:
        try:
            if os.path.exists(TOKEN_FILE):
                with open(TOKEN_FILE, 'r') as f:
                    token_cache = json.load(f)
            cache_loaded = True
        except Exception as e:
            logger.error(f"Error loading tokens: {str(e)}")
    return token_cache

async def save_token(user_id, account_type, token, website):
    global token_cache
    try:
        tokens = load_tokens()
        if str(user_id) not in tokens:
            tokens[str(user_id)] = {}
        if website not in tokens[str(user_id)]:
            tokens[str(user_id)][website] = {}
        tokens[str(user_id)][website][account_type] = token
        token_cache = tokens
        async with aiofiles.open(TOKEN_FILE, 'w') as f:
            await f.write(json.dumps(tokens, indent=4))
        logger.info(f"Token saved for user {user_id} ({account_type} account, {website})")
    except Exception as e:
        logger.error(f"Error saving token for user {user_id}: {str(e)}")

async def remove_token(user_id, account_type=None, website=None):
    global token_cache
    try:
        tokens = load_tokens()
        if str(user_id) in tokens:
            if website and account_type:
                if website in tokens[str(user_id)] and account_type in tokens[str(user_id)][website]:
                    del tokens[str(user_id)][website][account_type]
                    logger.info(f"Token removed for user {user_id} ({account_type} account, {website})")
            elif website:
                if website in tokens[str(user_id)]:
                    del tokens[str(user_id)][website]
                    logger.info(f"All tokens removed for user {user_id} ({website})")
            else:
                del tokens[str(user_id)]
                logger.info(f"All tokens removed for user {user_id}")
            token_cache = tokens
            async with aiofiles.open(TOKEN_FILE, 'w') as f:
                await f.write(json.dumps(tokens, indent=4))
            return True
        return False
    except Exception as e:
        logger.error(f"Error removing token for user {user_id}: {str(e)}")
        return False

async def reset_all(user_id):
    try:
        await remove_token(user_id)
        if os.path.exists(device_manager.base_dir):
            shutil.rmtree(device_manager.base_dir)
        os.makedirs(device_manager.base_dir, exist_ok=True)
        for website in WEBSITE_CONFIGS:
            track_file = f"online_durations_{website.lower()}.json"
            if os.path.exists(track_file):
                os.remove(track_file)
        if os.path.exists("bot.log"):
            os.remove("bot.log")
            logger.info(f"Log file bot.log deleted by user {user_id} during reset_all")
        logger.info(f"Reset all completed by user {user_id}, devices, cookies, and proxies cleared. Used devices preserved.")
        return True, (
            f"✅ Reset all completed successfully.\n\n"
            f"Please set a new User Agent using 'Set User Agent' and optionally a new proxy using 'Set Proxy' to create a new device identity."
        )
    except Exception as e:
        logger.error(f"Error resetting all for user {user_id}: {str(e)}")
        return False, f"❌ Error resetting all: {str(e)}"

async def encrypt_phone(phone):
    try:
        phone = phone.replace("+", "")
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        padded = pad(phone.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return b64encode(encrypted).decode()
    except Exception as e:
        logger.error(f"Error encrypting phone: {str(e)}")
        raise

def encrypt_username(plain_text: str) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

async def login_with_credentials(username, password, website_config, device_name):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
                url = f"{website_config['api_domain']}{website_config['login_path']}"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": get_random_accept_encoding(),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "origin": website_config['origin'],
                    "x-requested-with": "mark.via.gp",
                    "referer": website_config['referer'],
                    "accept-language": ACCEPT_LANGUAGE,
                    "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
                    "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
                    "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                    **get_random_sec_fetch_headers(),
                    "priority": get_random_priority()
                }
                data = {
                    "username": username,
                    "password": password
                }
                await asyncio.sleep(random.uniform(0.5, 2.0))
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        response_data = await response.json()
                        if response_data.get("code") == 1:
                            token = response_data.get("data", {}).get("token")
                            if not token:
                                token = response_data.get("data", {}).get("userinfo", {}).get("token")
                            if token:
                                return {
                                    "success": True,
                                    "token": token,
                                    "response": response_data
                                }
                            return {
                                "success": False,
                                "error": "Login successful but no token received",
                                "response": response_data
                            }
                        return {
                            "success": False,
                            "error": response_data.get("msg", "Unknown error"),
                            "response": response_data
                        }
            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    error_msg = f"Request timed out after {REQUEST_TIMEOUT} seconds"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg,
                        "response": None
                    }
                await asyncio.sleep(1)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    error_msg = f"Connection error: {str(e)}"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg,
                        "response": None
                    }
                await asyncio.sleep(1)

async def register_account(website_config, phone_number, password, confirm_password, invite_code, device_name, reg_host):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
                encrypted_username = encrypt_username(phone_number)
                url = f"{website_config['api_domain']}{website_config['signup_path']}"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": get_random_accept_encoding(),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                    "accept-language": ACCEPT_LANGUAGE,
                    "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
                    "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
                    "token": "",
                    "origin": website_config['origin'],
                    "x-requested-with": "mark.via.gp",
                    "referer": website_config['referer'],
                    "priority": get_random_priority()
                }
                data = {
                    "username": encrypted_username,
                    "password": password,
                    "confirm_password": confirm_password,
                    website_config['referral_field']: invite_code if invite_code else "",
                    "reg_host": reg_host
                }
                logger.info(f"Sending registration request to {url} for attempt {attempt + 1}/{MAX_RETRIES}")
                await asyncio.sleep(random.uniform(0.5, 2.0))
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        if response.status != 200:
                            logger.error(f"Registration failed with status {response.status} for {website_config['name']}")
                            if attempt == MAX_RETRIES - 1:
                                return {
                                    "code": -1,
                                    "msg": f"Registration failed with HTTP status {response.status}",
                                    "data": None
                                }
                            await asyncio.sleep(1)
                            continue
                        response_data = await response.json()
                        logger.info(f"Registration response for {website_config['name']}: {json.dumps(response_data, indent=2)}")
                        return response_data
            except asyncio.TimeoutError:
                logger.error(f"Registration request timed out after {REQUEST_TIMEOUT} seconds for {website_config['name']}")
                if attempt == MAX_RETRIES - 1:
                    return {
                        "code": -1,
                        "msg": f"Registration request timed out after {REQUEST_TIMEOUT} seconds",
                        "data": None
                    }
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Error in register_account for {website_config['name']}: {str(e)}")
                if attempt == MAX_RETRIES - 1:
                    return {
                        "code": -1,
                        "msg": f"Registration failed: {str(e)}",
                        "data": None
                    }
                await asyncio.sleep(1)
        logger.error(f"Registration failed after {MAX_RETRIES} attempts for {website_config['name']}")
        return {
            "code": -1,
            "msg": f"Registration failed after {MAX_RETRIES} attempts",
            "data": None
        }

async def send_code(token, phone_encrypted, website_config, device_name, phone_plain=None):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
                # ✅ ফোন নাম্বার থেকে কান্ট্রি কোড বের করা
                area_code = "1"
                if phone_plain:
                    match = re.match(r'^\+?(\d{1,4})', phone_plain)
                    if match:
                        code = match.group(1)
                        area_map = {
                            "880": "880",  # Bangladesh
                            "1": "1",      # USA/Canada
                            "91": "91",    # India
                            "44": "44",    # UK
                            "62": "62",    # Indonesia
                            "60": "60",    # Malaysia
                            "63": "63",    # Philippines
                            "66": "66",    # Thailand
                            "84": "84",    # Vietnam
                            "81": "81",    # Japan
                            "82": "82",    # Korea
                            "86": "86"     # China
                        }
                        area_code = area_map.get(code, "1")

                url = f"{website_config['api_domain']}{website_config['send_code_path']}"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": get_random_accept_encoding(),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "token": token,
                    "origin": website_config['origin'],
                    "x-requested-with": "mark.via.gp",
                    "referer": website_config['referer'],
                    "accept-language": ACCEPT_LANGUAGE,
                    "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
                    "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
                    "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                    **get_random_sec_fetch_headers(),
                    "priority": get_random_priority()
                }

                # Updated data format for new API
                data = {
                    "phone": phone_encrypted,
                    "area_code": area_code,
                    "send_type": "1"  # New required field
                }

                await asyncio.sleep(random.uniform(0.5, 2.0))
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        response_data = await response.json()

                        # ✅ নতুন কন্ডিশন — যদি area_code সাপোর্টেড না হয়
                        if response_data.get("code") == -31 or "Please select area code" in response_data.get("msg", ""):
                            return {
                                "code": -31,
                                "msg": "❌ এই এরিয়া কোড বর্তমানে সাপোর্টেড নয়। দয়া করে এডমিনের সাথে যোগাযোগ করুন।",
                                "time": str(int(time.time())),
                                "data": None
                            }

                        # আগের "too frequent" চেক আগের মতো থাকবে
                        if response_data.get("code") == 0 and response_data.get("msg") == "Frequent requests, please wait!!":
                            logger.info(f"Frequent requests error detected, waiting 2 seconds to retry (attempt {attempt + 1}/{MAX_RETRIES})")
                            await asyncio.sleep(2)
                            continue

                        return response_data

            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Send code timed out after {REQUEST_TIMEOUT} seconds")
                    return {
                        "code": -1,
                        "msg": f"Request timed out after {REQUEST_TIMEOUT} seconds",
                        "time": str(int(time.time())),
                        "data": None
                    }
                await asyncio.sleep(1)

            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Error in send_code after {MAX_RETRIES} attempts: {str(e)}")
                    return {
                        "code": -1,
                        "msg": f"Request failed after {MAX_RETRIES} attempts: {str(e)}",
                        "time": str(int(time.time())),
                        "data": None
                    }
                await asyncio.sleep(1)

        logger.error(f"Send code failed after {MAX_RETRIES} attempts")
        return {
            "code": -1,
            "msg": f"Request failed after {MAX_RETRIES} attempts",
            "time": str(int(time.time())),
            "data": None
        }

async def get_code(token, phone_plain, website_config, device_name):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
                url = f"{website_config['api_domain']}{website_config['get_code_path']}"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": get_random_accept_encoding(),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "token": token,
                    "origin": website_config['origin'],
                    "x-requested-with": "mark.via.gp",
                    "referer": website_config['referer'],
                    "accept-language": ACCEPT_LANGUAGE,
                    "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
                    "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
                    "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                    **get_random_sec_fetch_headers(),
                    "priority": get_random_priority()
                }
                
                # Updated data format for new API
                data = {
                    "is_agree": "1", 
                    "phone": phone_plain.replace("+", "")
                }
                
                logger.info(f"🔍 Getting OTP code for: {phone_plain}")
                logger.info(f"🔍 URL: {url}")
                logger.info(f"🔍 Data: {data}")
                
                await asyncio.sleep(random.uniform(0.5, 2.0))
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        response_text = await response.text()
                        logger.info(f"🔍 OTP Response status: {response.status}")
                        logger.info(f"🔍 OTP Response text: {response_text}")
                        
                        try:
                            response_data = await response.json()
                            logger.info(f"🔍 OTP Response JSON: {json.dumps(response_data, indent=2)}")
                            
                            # FIXED: Multiple possible locations for OTP code
                            otp = None
                            
                            # Try different possible response formats
                            if response_data.get("code") == 1:
                                data_field = response_data.get("data", {})
                                
                                # Format 1: Direct code in data
                                if isinstance(data_field, dict):
                                    otp = data_field.get("code")
                                # Format 2: Code in nested structure  
                                elif isinstance(data_field, str):
                                    # Sometimes data is a JSON string
                                    try:
                                        nested_data = json.loads(data_field)
                                        otp = nested_data.get("code")
                                    except:
                                        pass
                                
                                # Format 3: Code directly in response
                                if not otp:
                                    otp = response_data.get("code_value")
                                
                                # Format 4: Check msg field for code
                                if not otp:
                                    msg = response_data.get("msg", "")
                                    # Extract 6-digit code from message
                                    code_match = re.search(r'\b\d{6}\b', msg)
                                    if code_match:
                                        otp = code_match.group(0)
                                
                                logger.info(f"🔍 Extracted OTP: {otp}")
                                
                            return response_data
                            
                        except Exception as e:
                            logger.error(f"❌ Error parsing OTP response: {str(e)}")
                            return {"code": -1, "msg": f"Parse error: {str(e)}"}
                        
            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Get code timed out after {REQUEST_TIMEOUT} seconds")
                    raise
                await asyncio.sleep(1)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Error in get_code: {str(e)}")
                    raise
                await asyncio.sleep(1)

async def get_phone_list(token, account_type, website_config, device_name):
    async with await device_manager.build_session(device_name) as session:
        if not token or len(token) < 10:
            logger.error(f"Invalid or missing token for {account_type} account")
            return f"❌ Invalid or missing token for {account_type} account. Please login first using 'Log in Account'."
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': get_random_accept_encoding(),
            'token': token,
            'Origin': website_config['origin'],
            'Referer': website_config['referer'],
            'X-Requested-With': 'mark.via.gp',
            "accept-language": ACCEPT_LANGUAGE,
            "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
            "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            **get_random_sec_fetch_headers(),
            "priority": get_random_priority()
        }

        logger.info(f"Fetching phone list for {account_type} account ({website_config['name']})")
        try:
            await asyncio.sleep(random.uniform(0.5, 2.0))
            async with asyncio.timeout(REQUEST_TIMEOUT):
                async with session.post(website_config['phone_list_url'], headers=headers) as response:
                    response.raise_for_status()
                    data = await response.json()
        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                logger.error(f"401 Unauthorized for {account_type} account ({website_config['name']}): {str(e)}")
                return f"❌ Unauthorized access for {account_type} account ({website_config['name']}). Token may be invalid or expired. Please login again using 'Log in Account'."
            logger.error(f"HTTP error for {account_type} account ({website_config['name']}): {str(e)}")
            return f"❌ Error while calling API for {account_type} account ({website_config['name']}): {str(e)}"
        except asyncio.TimeoutError:
            logger.error(f"Phone list request timed out after {REQUEST_TIMEOUT} seconds")
            return f"❌ Request timed out for {account_type} account ({website_config['name']})."
        except Exception as e:
            logger.error(f"Request error for {account_type} account ({website_config['name']}): {str(e)}")
            return f"❌ Error while calling API for {account_type} account ({website_config['name']}): {str(e)}"

        if data.get("code") != 1:
            logger.error(f"API response error for {account_type} ({website_config['name']}): {data.get('msg', 'Unknown error')}")
            return f"❌ Invalid token or no data found for {account_type} account ({website_config['name']}): {data.get('msg', 'Unknown error')}"

        # Updated data parsing for new API response format
        phones_data = data.get("data", {})
        if isinstance(phones_data, dict):
            phones_list = phones_data.get("list", [])
        else:
            phones_list = phones_data or []
            
        phones = phones_list
        now = format_bd_time()

        total = len(phones)
        online = sum(1 for p in phones if p.get("status") == 1)
        offline = total - online

        output = [
            f"🕒 Last Updated: {now} (Bangladesh Time)",
            f"🔗 Total Linked: {total}",
            f"🟢 Online: {online}",
            f"🔴 Offline: {offline}\n",
            f"📱 Phone Numbers Status ({website_config['name']}):"
        ]

        for idx, phone_data in enumerate(phones, 1):
            # Updated phone number extraction for new format
            phone_num = phone_data.get("phone", "")
            phone = "+1" + str(phone_num)[-10:] if phone_num else ""
            status = phone_data.get("status", 0)
            this_login_sends = phone_data.get("this_login_sends", 0)
            send_type = phone_data.get("send_type", 0)

            status_icon = "🟢" if status == 1 else "🔴"
            output.append(
                f"{idx:2d}. {phone} {status_icon} | 📤 {this_login_sends} | 🔄 Manual"
            )

        output.append("\n📊 Additional Info:")
        output.append("• 📤 This Login Sends")
        output.append("• 🔄 Send Type")

        return "\n".join(output)

async def get_task_statistics(token, website_config, device_name):
    """Get task statistics from the API"""
    async with await device_manager.build_session(device_name) as session:
        if not token or len(token) < 10:
            return "❌ Invalid or missing token. Please login first using 'Log in Account'."
        
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': get_random_accept_encoding(),
            'token': token,
            'Origin': website_config['origin'],
            'Referer': website_config['referer'],
            'X-Requested-With': 'mark.via.gp',
            "accept-language": ACCEPT_LANGUAGE,
            "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
            "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            **get_random_sec_fetch_headers(),
            "priority": get_random_priority()
        }

        logger.info(f"Fetching task statistics for {website_config['name']}")
        try:
            await asyncio.sleep(random.uniform(0.5, 2.0))
            async with asyncio.timeout(REQUEST_TIMEOUT):
                async with session.get(website_config['task_stat_url'], headers=headers) as response:
                    response.raise_for_status()
                    data = await response.json()
        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                logger.error(f"401 Unauthorized for task statistics ({website_config['name']}): {str(e)}")
                return f"❌ Unauthorized access for task statistics ({website_config['name']}). Token may be invalid or expired. Please login again using 'Log in Account'."
            logger.error(f"HTTP error for task statistics ({website_config['name']}): {str(e)}")
            return f"❌ Error while calling API for task statistics ({website_config['name']}): {str(e)}"
        except asyncio.TimeoutError:
            logger.error(f"Task statistics request timed out after {REQUEST_TIMEOUT} seconds")
            return f"❌ Request timed out for task statistics ({website_config['name']})."
        except Exception as e:
            logger.error(f"Request error for task statistics ({website_config['name']}): {str(e)}")
            return f"❌ Error while calling API for task statistics ({website_config['name']}): {str(e)}"

        if data.get("code") != 1:
            logger.error(f"API response error for task statistics ({website_config['name']}): {data.get('msg', 'Unknown error')}")
            return f"❌ Error fetching task statistics ({website_config['name']}): {data.get('msg', 'Unknown error')}"

        stats_data = data.get("data", {})
        now = format_bd_time()

        output = [
            f"📊 Task Statistics ({website_config['name']})\n",
            f"📅 Today's Performance:",
            f"• 📤 Today Send Times: {stats_data.get('today_send_times', 0)}",
            f"• 💰 Today Income Score: {stats_data.get('today_income_score', 0)}",
            f"• 📈 Yesterday Income Score: {stats_data.get('yesterday_income_score', 0)}\n",
            f"🕒 Last Updated: {now} (Bangladesh Time)"
        ]

        return "\n".join(output)

async def bulk_send_messages(token, website_config, device_name):
    """Bulk send messages to all phone numbers - FIXED VERSION"""
    async with await device_manager.build_session(device_name) as session:
        if not token or len(token) < 10:
            return "❌ Invalid or missing token. Please login first using 'Log in Account'."
        
        # First get phone list
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Content-Type': 'application/json',
            'token': token,
            'Origin': website_config['origin'],
            'Referer': website_config['referer'],
            'X-Requested-With': 'com.diy22ssc.whatsapp',  # FIXED: This was missing
            'User-Agent': 'Mozilla/5.0 (Linux; Android 16; SM-M356B Build/BP2A.250605.031.A3; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/142.0.7444.102 Mobile Safari/537.36',
            'sec-ch-ua-platform': '"Android"',
            'sec-ch-ua': '"Chromium";v="142", "Android WebView";v="142", "Not_A Brand";v="99"',
            'sec-ch-ua-mobile': '?1',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'priority': 'u=1, i'
        }

        # Get phone numbers first
        try:
            logger.info(f"🔍 Fetching phone list from: {website_config['phone_list_url']}")
            async with asyncio.timeout(REQUEST_TIMEOUT):
                async with session.post(website_config['phone_list_url'], headers=headers) as response:
                    response.raise_for_status()
                    phone_data = await response.json()
                    logger.info(f"📱 Phone list response: {json.dumps(phone_data, indent=2)}")
        except Exception as e:
            logger.error(f"❌ Error fetching phone list for bulk send: {str(e)}")
            return f"❌ Error fetching phone list: {str(e)}"

        if phone_data.get("code") != 1:
            logger.error(f"❌ Phone list API error: {phone_data.get('msg', 'Unknown error')}")
            return f"❌ Error fetching phone list: {phone_data.get('msg', 'Unknown error')}"

        phones_data = phone_data.get("data", {})
        if isinstance(phones_data, dict):
            phones_list = phones_data.get("list", [])
        else:
            phones_list = phones_data or []

        if not phones_list:
            return "❌ No phone numbers found to send messages."

        logger.info(f"📞 Found {len(phones_list)} phone numbers for bulk send")

        # Prepare for bulk send
        results = []
        successful = 0
        failed = 0

        output = ["🚀 Starting Bulk Send...\n"]

        for idx, phone_info in enumerate(phones_list, 1):
            phone_num = phone_info.get("phone", "")
            if not phone_num:
                continue

            phone_str = str(phone_num)
            phone_display = "+1" + phone_str[-10:] if phone_str else ""

            try:
                # FIXED: Use the exact same headers as your curl command
                send_headers = {
                    'User-Agent': 'Mozilla/5.0 (Linux; Android 16; SM-M356B Build/BP2A.250605.031.A3; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/142.0.7444.102 Mobile Safari/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Encoding': 'gzip, deflate, br, zstd',
                    'Content-Type': 'application/json',
                    'sec-ch-ua-platform': '"Android"',
                    'sec-ch-ua': '"Chromium";v="142", "Android WebView";v="142", "Not_A Brand";v="99"',
                    'sec-ch-ua-mobile': '?1',
                    'origin': website_config['origin'],
                    'x-requested-with': 'com.diy22ssc.whatsapp',
                    'sec-fetch-site': 'cross-site',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-dest': 'empty',
                    'referer': website_config['referer'],
                    'accept-language': 'en,en-US;q=0.9,ga-IE;q=0.8,ga;q=0.7',
                    'priority': 'u=1, i'
                }

                # FIXED: Use the exact data format from your curl command
                send_data = {"phone": int(phone_num)}
                
                # FIXED: Use the correct bulk send URL
                bulk_send_url = website_config['bulk_send_url']
                
                logger.info(f"🔍 Sending to {phone_display} via URL: {bulk_send_url}")
                logger.info(f"🔍 Request data: {send_data}")

                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(bulk_send_url, 
                                          headers=send_headers, 
                                          json=send_data,
                                          ssl=False) as response:  # FIXED: Added ssl=False
                        
                        response_status = response.status
                        response_text = await response.text()
                        
                        logger.info(f"🔍 Response status: {response_status}")
                        logger.info(f"🔍 Response text: {response_text}")
                        
                        try:
                            send_response = await response.json()
                            logger.info(f"🔍 Response JSON: {json.dumps(send_response, indent=2)}")
                        except:
                            send_response = {"code": -1, "msg": f"Invalid JSON response: {response_text}"}
                            logger.error(f"❌ Invalid JSON response: {response_text}")

                # FIXED: Check for success based on actual API response
                if send_response.get("code") == 0 or send_response.get("code") == 1:
                    results.append(f"{idx}. {phone_display} ✅ Success")
                    successful += 1
                    logger.info(f"✅ Successfully sent to {phone_display}")
                else:
                    error_msg = send_response.get('msg', 'Unknown error')
                    detailed_error = f"{error_msg} (Status: {response_status})"
                    results.append(f"{idx}. {phone_display} ❌ Failed - {detailed_error}")
                    failed += 1
                    logger.error(f"❌ Failed to send to {phone_display}: {detailed_error}")

                # Small delay between requests
                await asyncio.sleep(1)  # Increased delay to avoid rate limiting

            except asyncio.TimeoutError:
                error_msg = "Request timeout"
                results.append(f"{idx}. {phone_display} ❌ Failed - {error_msg}")
                failed += 1
                logger.error(f"❌ Timeout for {phone_display}")
                
            except Exception as e:
                error_msg = f"{type(e).__name__}: {str(e)}"
                results.append(f"{idx}. {phone_display} ❌ Failed - {error_msg}")
                failed += 1
                logger.error(f"❌ Exception for {phone_display}: {error_msg}")

        now = format_bd_time()
        total = len(phones_list)
        success_rate = (successful / total) * 100 if total > 0 else 0

        # Build final output
        output.append(f"✅ Successfully Sent: {successful}/{total}")
        output.append(f"❌ Failed: {failed}/{total}\n")
        
        output.append("📱 Send Status:")
        output.extend(results)
        
        output.append(f"\n📊 Summary:")
        output.append(f"• Total Numbers: {total}")
        output.append(f"• Successful: {successful}")
        output.append(f"• Failed: {failed}")
        output.append(f"• Success Rate: {success_rate:.1f}%\n")
        
        output.append(f"🕒 Last Updated: {now} (Bangladesh Time)")

        return "\n".join(output)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    logger.info(f"Start command triggered by user {user_id}")
    
    try:
        tokens = load_tokens()
        context.user_data.clear()
        context.user_data['selected_website'] = DEFAULT_SELECTED_WEBSITE
        
        # FIXED: Properly check if user has tokens
        user_has_account = False
        user_tokens = tokens.get(str(user_id), {})
        
        if user_tokens:
            for website in WEBSITE_CONFIGS:
                website_tokens = user_tokens.get(website, {})
                if isinstance(website_tokens, dict) and website_tokens.get('main'):
                    user_has_account = True
                    break
        
        logger.info(f"Token cache for user {user_id}: {'Present' if user_has_account else 'None'}")

        welcome_message = "👋 Welcome to the WhatsApp Linking Bot!\n\nThis System made by HASAN."
        
        if user_has_account:
            selected_website = context.user_data['selected_website']
            message = f"✅ You have accounts setup!\n\n{welcome_message}"
            logger.info(f"User {user_id} has account, showing welcome message")
            await update.message.reply_text(message, reply_markup=get_main_keyboard(selected_website, user_id))
        else:
            logger.info(f"User {user_id} has no account, showing welcome message")
            await update.message.reply_text(
                welcome_message,
                reply_markup=get_main_keyboard(DEFAULT_SELECTED_WEBSITE, user_id)
            )
            
    except Exception as e:
        logger.error(f"Error in start command for user {user_id}: {str(e)}")
        await update.message.reply_text(
            "👋 Welcome to the WhatsApp Linking Bot!\n\nThis System made by HASAN.",
            reply_markup=get_main_keyboard(DEFAULT_SELECTED_WEBSITE, user_id)
        )

async def login_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    text = update.message.text.strip()
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    logger.info(f"Login command triggered by user {user_id} for {selected_website}")
    
    if text.startswith('/login ') and len(context.args) > 0:
        token = context.args[0].strip()
        if len(token) > 10:
            device_name = str(user_id)
            if not device_manager.exists(device_name):
                logger.error(f"No device set for user {user_id}")
                await update.message.reply_text(
                    "❌ Please set a User Agent first using 'Set User Agent'.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                return
            await save_token(user_id, 'main', token, selected_website)
            context.user_data.clear()
            context.user_data['selected_website'] = selected_website
            logger.info(f"User {user_id} saved account token via /login for {selected_website}")
            await update.message.reply_text(
                f"✅ Account login successful for {selected_website}!\nAccount token: <code>{token[:10]}...</code>",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        else:
            logger.error(f"User {user_id} provided invalid token via /login for {selected_website}")
            await update.message.reply_text(
                "❌ Invalid token format. Token should be longer than 10 characters.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        return

    context.user_data['state'] = 'awaiting_website_selection_login'
    logger.info(f"User {user_id} state set to awaiting_website_selection_login via /login")
    await update.message.reply_text(
        f"Please select a website for account login:",
        reply_markup=get_website_selection_keyboard()
    )

async def handle_credentials(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    text = update.message.text.strip()
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    website = selected_website
    website_config = WEBSITE_CONFIGS[website]
    device_name = str(user_id)
    if not device_manager.exists(device_name):
        await update.message.reply_text(
            "❌ Please set user agent first using 'Set User Agent'.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    logger.info(f"Handling credentials for user {user_id} on {website}")

    if ":" in text:
        username, password = text.split(":", 1)
        username = username.strip()
        password = password.strip()
        await update.message.reply_text("⏳ Attempting login...")
        login_result = await login_with_credentials(username, password, website_config, device_name)
        if login_result["success"]:
            account_type = 'main'
            await save_token(user_id, account_type, login_result["token"], website)
            context.user_data.clear()
            context.user_data['selected_website'] = selected_website
            logger.info(f"User {user_id} login successful for {account_type} account on {website}")
            await update.message.reply_text(
                f"✅ Account login successful for {website}!\nAccount token: <code>{login_result['token'][:10]}...</code>",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        else:
            error_details = (
                f"❌ Login Failed\n\n"
                f"Error: {login_result['error']}\n"
                f"Response: {json.dumps(login_result['response'], indent=2) if login_result['response'] else 'None'}"
            )
            logger.error(f"Login failed for user {user_id} on {website}: {error_details}")
            await update.message.reply_text(
                f"<pre>{error_details}</pre>",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        return

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    user_state = context.user_data.get('state', '')
    text = update.message.text.strip()
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    try:
        tokens = load_tokens()
        
        logger.info(f"Message from user {user_id} on selected: {selected_website}, text: '{text}', state: {user_state}")

        # Check if user has any logged-in websites - FIXED
        user_websites = []
        user_tokens = tokens.get(str(user_id), {})
        
        if user_tokens:
            for website in WEBSITE_CONFIGS:
                website_tokens = user_tokens.get(website, {})
                if isinstance(website_tokens, dict) and website_tokens.get('main'):
                    user_websites.append(website)

        if text in WEBSITE_CONFIGS.keys() and user_state in ['awaiting_website_selection_login', 'awaiting_website_selection_register', 'awaiting_website_selection_task_stat', 'awaiting_website_selection_bulk_send']:
            if user_state == 'awaiting_website_selection_login':
                context.user_data['selected_website'] = text
                context.user_data['state'] = 'awaiting_login'
                await update.message.reply_text(
                    f"✅ Selected website: {text}\nPlease enter your token or username:password for the {text} account.",
                    reply_markup=get_main_keyboard(text, user_id)
                )
            elif user_state == 'awaiting_website_selection_register':
                context.user_data['register_website'] = text
                context.user_data['register_account_type'] = 'main'
                context.user_data['state'] = 'registering'
                await update.message.reply_text(
                    f"✅ Selected website: {text}\n📱 ফোন নাম্বার দিন:",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
            elif user_state == 'awaiting_website_selection_task_stat':
                context.user_data['selected_website'] = text
                await task_statistics_command(update, context)
            elif user_state == 'awaiting_website_selection_bulk_send':
                context.user_data['selected_website'] = text
                await bulk_send_command(update, context)
            return
        elif text == "Back to Main Menu" and user_state in ['awaiting_website_selection_login', 'awaiting_website_selection_register', 'awaiting_website_selection_task_stat', 'awaiting_website_selection_bulk_send']:
            context.user_data['state'] = ''
            await update.message.reply_text(
                f"✅ Returned to main menu.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return
        elif text == "Log in Account":
            context.user_data['state'] = 'awaiting_website_selection_login'
            await update.message.reply_text(
                f"🌐 Please select a website for account login:",
                reply_markup=get_website_selection_keyboard()
            )
            return
        elif text == f"Link {selected_website} WhatsApp":
            await link_command(update, context)
            return
        elif text == f"{selected_website} Number List":
            await phone_list_command(update, context)
            return
        elif text == "Register Account":
            context.user_data['state'] = 'awaiting_website_selection_register'
            await update.message.reply_text(
                f"🌐 Please select a website for account registration:",
                reply_markup=get_website_selection_keyboard()
            )
            return
        elif text == "Task Statistics":
            # FIXED: Use currently logged-in website instead of asking for selection
            if len(user_websites) == 1:
                # If only one website is logged in, use it directly
                context.user_data['selected_website'] = user_websites[0]
                await task_statistics_command(update, context)
            elif len(user_websites) > 1:
                # If multiple websites, ask for selection
                context.user_data['state'] = 'awaiting_website_selection_task_stat'
                await update.message.reply_text(
                    f"🌐 Please select a website for task statistics:",
                    reply_markup=get_website_selection_keyboard()
                )
            else:
                await update.message.reply_text(
                    "❌ No accounts found. Please login first using 'Log in Account'.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
            return
        elif text == "Bulk Send":
            # FIXED: Use currently logged-in website instead of asking for selection
            if len(user_websites) == 1:
                # If only one website is logged in, use it directly
                context.user_data['selected_website'] = user_websites[0]
                await bulk_send_command(update, context)
            elif len(user_websites) > 1:
                # If multiple websites, ask for selection
                context.user_data['state'] = 'awaiting_website_selection_bulk_send'
                await update.message.reply_text(
                    f"🌐 Please select a website for bulk send:",
                    reply_markup=get_website_selection_keyboard()
                )
            else:
                await update.message.reply_text(
                    "❌ No accounts found. Please login first using 'Log in Account'.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
            return
        elif text.startswith("Set User Agent") or text.startswith("✅ Set User Agent"):
            device_name = str(user_id)
            try:
                profile = await device_manager.create_new_device(device_name)
                await update.message.reply_text(
                    f"✅ New realistic device created and User Agent set:\n<code>{profile.ua}</code>\n\n"
                    f"Device ID: {profile.device_id[:10]}...\nNew device identity created.",
                    parse_mode='HTML',
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                logger.info(f"User {user_id} created new device: UA {profile.ua}")
            except Exception as e:
                logger.error(f"Error creating device for user {user_id}: {str(e)}")
                await update.message.reply_text(
                    f"❌ Error creating device: {str(e)}",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
            return
        elif text.startswith("Set Proxy") or text.startswith("✅ Set Proxy"):
            if not device_manager.exists(str(user_id)):
                await update.message.reply_text(
                    "❌ Please set user agent first using 'Set User Agent'.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                return
            await update.message.reply_text("📡 Setting up proxy automatically...")
            success, proxy_info, message = await device_manager.auto_set_proxy(str(user_id))
            if success:
                response = (
                    f"✅ {message}\n\n"
                    f"🌐 Public IP: {proxy_info['public_ip']}\n\n"
                    f"📍 Location Information:\n"
                    f"Country: {proxy_info['location']['country']}\n"
                    f"Region: {proxy_info['location']['region']}\n"
                    f"City: {proxy_info['location']['city']}\n"
                    f"ZIP Code: {proxy_info['location']['zip_code']}\n"
                    f"Latitude: {proxy_info['location']['latitude']}\n"
                    f"Longitude: {proxy_info['location']['longitude']}\n"
                    f"Timezone: {proxy_info['location']['timezone']}\n\n"
                    f"🏢 Network Information:\n"
                    f"ISP: {proxy_info['network']['isp']}\n"
                    f"Organization: {proxy_info['network']['organization']}\n"
                    f"AS Number: {proxy_info['network']['as_number']}\n"
                    f"Proxy/VPN: {proxy_info['network']['proxy_vpn']}\n"
                    f"Hosting: {proxy_info['network']['hosting']}"
                )
                logger.info(f"Proxy automatically set for user {user_id}")
            else:
                response = f"❌ {message}"
                logger.error(f"Failed to set proxy for user {user_id}: {message}")
            await update.message.reply_text(
                response,
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return
        elif text == "Manual Proxy":
            if not device_manager.exists(str(user_id)):
                await update.message.reply_text(
                    "❌ Please set user agent first using 'Set User Agent'.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                return
            context.user_data['state'] = 'awaiting_manual_proxy'
            await update.message.reply_text(
                "📡 Please enter proxy in format: host:port:username:password\n\nExample: 192.168.1.1:8080:user123:pass123",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return
        elif text == "Reset All":
            context.user_data['state'] = 'confirm_reset_all'
            await update.message.reply_text(
                "আপনি কি নিশ্চিত যে সবকিছু রিসেট করতে চান? এটি সকল ডেটা এবং লগ ফাইল মুছে ফেলবে। আপনাকে নতুন ইউজার এজেন্ট ম্যানুয়ালি সেট করতে হবে।",
                reply_markup=get_confirmation_keyboard()
            )
            return

        if user_state == 'confirm_reset_all':
            if text == "Yes":
                success, message = await reset_all(user_id)
                context.user_data.clear()
                await update.message.reply_text(
                    message,
                    parse_mode='HTML',
                    reply_markup=get_main_keyboard(DEFAULT_SELECTED_WEBSITE, user_id)
                )
            elif text == "No":
                await update.message.reply_text(
                    "✅ রিসেট বাতিল করা হয়েছে।",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
            context.user_data['state'] = ''
            return
        elif user_state == 'awaiting_manual_proxy':
            success = await device_manager.set_proxy(str(user_id), text)
            if success:
                profile = device_manager.load(str(user_id))
                proxy_info = await fetch_proxy_info(profile.proxy)
                if proxy_info.get("success"):
                    response = (
                        f"✅ Manual proxy set successfully!\n\n"
                        f"🌐 Public IP: {proxy_info['public_ip']}\n\n"
                        f"📍 Location Information:\n"
                        f"Country: {proxy_info['location']['country']}\n"
                        f"Region: {proxy_info['location']['region']}\n"
                        f"City: {proxy_info['location']['city']}\n"
                        f"ZIP Code: {proxy_info['location']['zip_code']}\n"
                        f"Latitude: {proxy_info['location']['latitude']}\n"
                        f"Longitude: {proxy_info['location']['longitude']}\n"
                        f"Timezone: {proxy_info['location']['timezone']}\n\n"
                        f"🏢 Network Information:\n"
                        f"ISP: {proxy_info['network']['isp']}\n"
                        f"Organization: {proxy_info['network']['organization']}\n"
                        f"AS Number: {proxy_info['network']['as_number']}\n"
                        f"Proxy/VPN: {proxy_info['network']['proxy_vpn']}\n"
                        f"Hosting: {proxy_info['network']['hosting']}"
                    )
                else:
                    response = f"✅ Proxy set but connection test failed: {proxy_info.get('error')}"
            else:
                response = "❌ Invalid proxy format. Please use: host:port:username:password"
            
            context.user_data['state'] = ''
            await update.message.reply_text(
                response,
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return
        elif user_state == 'awaiting_login':
            if ":" in text:
                await handle_credentials(update, context)
            elif len(text) > 10:
                device_name = str(user_id)
                if not device_manager.exists(device_name):
                    await update.message.reply_text(
                        "❌ Please set user agent first using 'Set User Agent'.",
                        reply_markup=get_main_keyboard(selected_website, user_id)
                    )
                    return
                await save_token(user_id, 'main', text, selected_website)
                context.user_data['state'] = ''
                await update.message.reply_text(
                    f"✅ Account login successful for {selected_website}!\nAccount token: <code>{text[:10]}...</code>",
                    parse_mode='HTML',
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
            else:
                await update.message.reply_text(
                    "❌ Invalid input. Please provide a token (longer than 10 characters) or username:password.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
            return
        elif user_state == 'awaiting_phone':
            await process_phone_number(update, context)
            return
        elif user_state == 'registering':
            website = context.user_data['register_website']
            website_config = WEBSITE_CONFIGS[website]
            account_type = context.user_data.get('register_account_type', 'main')
            device_name = str(user_id)
            if not device_manager.exists(device_name):
                await update.message.reply_text(
                    "❌ Please set user agent first using 'Set User Agent'.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                context.user_data['state'] = ''
                return
            if 'reg_phone' not in context.user_data:
                context.user_data['reg_phone'] = text
                await update.message.reply_text("🔑 পাসওয়ার্ড দিন:")
                return
            elif 'reg_password' not in context.user_data:
                context.user_data['reg_password'] = text
                await update.message.reply_text("🔄 কনফার্ম পাসওয়ার্ড দিন (ম্যানুয়ালি টাইপ করুন):")
                return
            elif 'reg_confirm_password' not in context.user_data:
                context.user_data['reg_confirm_password'] = text
                await update.message.reply_text("🎁 রেফার কোড দিন (অপশনাল, স্কিপ করতে /skip লিখুন):")
                return
            else:
                invite_code_input = "" if text == "/skip" else text
                phone = context.user_data['reg_phone']
                password = context.user_data['reg_password']
                confirm_password = context.user_data['reg_confirm_password']
                reg_host = website_config['origin'].split('//')[1]
                
                if invite_code_input and len(invite_code_input) < 4:
                    await update.message.reply_text(
                        "❌ অবৈধ রেফার কোড। কোডটি কমপক্ষে ৪ অক্ষরের হতে হবে। আবার চেষ্টা করুন বা /skip ব্যবহার করুন।",
                        reply_markup=get_main_keyboard(selected_website, user_id)
                    )
                    return

                await update.message.reply_text(f"⏳ রেজিস্ট্রেশন চেষ্টা করা হচ্ছে...")
                response_data = await register_account(website_config, phone, password, confirm_password, invite_code_input, device_name, reg_host)
                
                if response_data is None or not isinstance(response_data, dict):
                    error_msg = "Server returned no response or invalid response"
                    logger.error(f"Registration failed for user {user_id} on {website}: {error_msg}")
                    await update.message.reply_text(
                        f"❌ রেজিস্ট্রেশন ব্যর্থ: {error_msg}\n\nআবার চেষ্টা করুন।",
                        reply_markup=get_main_keyboard(selected_website, user_id)
                    )
                    context.user_data['state'] = ''
                    if 'reg_phone' in context.user_data:
                        del context.user_data['reg_phone']
                    if 'reg_password' in context.user_data:
                        del context.user_data['reg_password']
                    if 'reg_confirm_password' in context.user_data:
                        del context.user_data['reg_confirm_password']
                    return

                if response_data.get("code") == 1:
                    await update.message.reply_text("✅ রেজিস্ট্রেশন সফল! অটো লগইন চেষ্টা করা হচ্ছে...")
                    login_result = await login_with_credentials(phone, password, website_config, device_name)
                    if login_result["success"]:
                        await save_token(user_id, account_type, login_result["token"], website)
                        context.user_data['selected_website'] = website
                        # ডায়নামিকভাবে referral_field ব্যবহার করা এবং None চেক
                        referral_field = website_config.get('referral_field', 'invite_code')
                        data = response_data.get("data")
                        invite_code = data.get(referral_field, "N/A") if isinstance(data, dict) else "N/A"
                        bd_time = get_bd_time()
                        formatted_time = format_bd_time(bd_time)
                        number = 1
                        if os.path.exists(REGISTRATION_FILE):
                            with open(REGISTRATION_FILE, 'r') as f:
                                lines = f.readlines()
                                if lines:
                                    last_number = 0
                                    for line in reversed(lines):
                                        if line.strip() and line.strip()[0].isdigit():
                                            try:
                                                last_number = int(line.split('.')[0])
                                                break
                                            except (ValueError, IndexError):
                                                continue
                                    number = last_number + 1
                        os.makedirs(os.path.dirname(REGISTRATION_FILE) or '.', exist_ok=True)
                        with open(REGISTRATION_FILE, 'a') as f:
                            f.write(f"{number}. Date: {bd_time.strftime('%Y-%m-%d')} Time: {bd_time.strftime('%H:%M:%S')}\n")
                            f.write(f"   Website: {website}\n")
                            f.write(f"   Username: {phone}\n")
                            f.write(f"   Password: {password}\n")
                            f.write(f"   Invite Code: {invite_code}\n")
                            f.write(f"   Used: no\n")
                            f.write("\n")
                        logger.info(f"Registration data saved for user {user_id} on {website} in {REGISTRATION_FILE}")
                        await update.message.reply_text(
                            f"✅ অটো লগইন সফল! টোকেন: {login_result['token'][:10]}...\n\n"
                            f"রেজিস্ট্রেশন ডেটা সেভ করা হয়েছে।",
                            reply_markup=get_main_keyboard(context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE), user_id)
                        )
                    else:
                        error_msg = login_result.get("error", "Unknown login error")
                        logger.error(f"Auto login failed for user {user_id} on {website}: {error_msg}")
                        await update.message.reply_text(
                            f"❌ অটো লগইন ব্যর্থ। ম্যানুয়াল লগইন করুন: ইউজারনেম:পাসওয়ার্ড বা টোকেন দিন।\n\nError: {error_msg}",
                            reply_markup=get_main_keyboard(selected_website, user_id)
                        )
                else:
                    error_msg = response_data.get("msg", "Unknown error")
                    logger.error(f"Registration failed for user {user_id} on {website}: {error_msg}")
                    await update.message.reply_text(
                        f"❌ রেজিস্ট্রেশন ব্যর্থ: {error_msg}\n\nপ্রতিক্রিয়া: {json.dumps(response_data, indent=2)}\n\nআবার চেষ্টা করুন।",
                        reply_markup=get_main_keyboard(selected_website, user_id)
                    )
                context.user_data['state'] = ''
                if 'reg_phone' in context.user_data:
                    del context.user_data['reg_phone']
                if 'reg_password' in context.user_data:
                    del context.user_data['reg_password']
                if 'reg_confirm_password' in context.user_data:
                    del context.user_data['reg_confirm_password']
                return
        else:
            await update.message.reply_text(
                "আমি এই কমান্ড বুঝতে পারিনি। মেনু থেকে একটি অপশন নির্বাচন করুন।",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            
    except Exception as e:
        logger.error(f"Error in handle_message for user {user_id}: {str(e)}")
        await update.message.reply_text(
            "❌ An error occurred. Please try again.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )

# Global variable to track all OTP processes
current_otp_processes = {}

async def process_phone_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = update.message.from_user.id
        phone = update.message.text.strip()
        selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
        account_type = 'main'
        website = selected_website
        website_config = WEBSITE_CONFIGS[website]
        device_name = str(user_id)

        # ✅ ইউজার এজেন্ট চেক
        if not device_manager.exists(device_name):
            await update.message.reply_text(
                "❌ প্রথমে 'Set User Agent' দিয়ে ইউজার এজেন্ট সেট করুন।",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return

        logger.info(f"Processing phone number for user {user_id}: {phone}")

        # ✅ নম্বর ক্লিন করা
        phone_clean = re.sub(r'[^\d+]', '', phone)
        if phone_clean.startswith('+'):
            normalized_phone = phone_clean
        elif phone_clean.startswith('1') and len(phone_clean) == 11:
            normalized_phone = '+' + phone_clean
        elif phone_clean.startswith('880') and len(phone_clean) == 13:
            normalized_phone = '+' + phone_clean
        elif len(phone_clean) == 10:
            normalized_phone = '+1' + phone_clean
        else:
            normalized_phone = '+' + phone_clean if phone_clean else None

        if not normalized_phone:
            await update.message.reply_text(
                "❌ অবৈধ ফোন নাম্বার। দয়া করে সঠিক কান্ট্রি কোডসহ নাম্বার দিন।",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return

        # ✅ টোকেন চেক করা
        tokens = load_tokens()
        token = tokens.get(str(user_id), {}).get(website, {}).get(account_type)
        if not token:
            context.user_data.pop('state', None)
            context.user_data['selected_website'] = selected_website
            await update.message.reply_text(
                f"❌ কোনো {website} একাউন্ট লগইন করা নেই। প্রথমে লগইন করুন।",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return

        # ✅ Duplicate check - একই number এর আগের process cancel করবে
        process_key = f"{user_id}_{normalized_phone}"
        if process_key in current_otp_processes:
            logger.info(f"🔄 Duplicate number found, cancelling previous: {normalized_phone}")
            current_otp_processes[process_key]['active'] = False
            # Wait a bit for previous process to clean up
            await asyncio.sleep(1)

        # ✅ ফোন এনক্রিপ্ট
        phone_encrypted = await encrypt_phone(normalized_phone)

        # ⏳ প্রসেসিং মেসেজ তৈরি করা
        processing_msg = await update.message.reply_text(f"📱 Processing: {normalized_phone}\n📤 Sending verification code...")

        # ✅ কোড পাঠানো (অটো area_code সহ)
        response = await send_code(token, phone_encrypted, website_config, device_name, phone_plain=normalized_phone)

        # 🔎 রেসপন্স চেক
        if response.get("code") == 1:
            await processing_msg.edit_text(
                f"📱 Processing: {normalized_phone}\n"
                f"✅ Verification code sent successfully!\n"
                f"🔍 Checking for OTP..."
            )
            
            # Start OTP fetching in background
            asyncio.create_task(
                fetch_otp_for_number(
                    user_id, normalized_phone, token, website_config, device_name, update, context, processing_msg
                )
            )
                
        elif response.get("code") == -31:
            await processing_msg.edit_text(f"❌ {normalized_phone} - এই এরিয়া কোড সাপোর্টেড নয়")
        else:
            error_msg = response.get('msg', 'অজানা ত্রুটি')
            await processing_msg.edit_text(f"❌ {normalized_phone} - কোড পাঠাতে ব্যর্থ: {error_msg}")

    except Exception as e:
        logger.error(f"Error in process_phone_number: {e}")
        await update.message.reply_text(
            f"❌ System Error: {str(e)}\n\nPlease try again or contact support.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )


async def fetch_otp_for_number(user_id, phone, token, website_config, device_name, update, context, processing_msg):
    """Background task to fetch OTP - WITH PROGRESS BAR"""
    process_key = f"{user_id}_{phone}"
    start_time = time.time()
    max_duration = 60
    
    current_otp_processes[process_key] = {
        'active': True,
        'phone': phone,
        'start_time': start_time,
        'message_sent': False,
        'processing_msg': processing_msg
    }
    
    try:
        check_count = 0
        
        while time.time() - start_time < max_duration:
            if not current_otp_processes.get(process_key, {}).get('active', False):
                await processing_msg.edit_text(f"🔄 {phone} - Cancelled")
                return
            
            check_count += 1
            current_time = time.time()
            elapsed_seconds = int(current_time - start_time)
            remaining_seconds = max_duration - elapsed_seconds
            progress_percent = min(100, int((elapsed_seconds / max_duration) * 100))
            
            # Progress bar
            progress_bar = "[" + "█" * (progress_percent // 5) + "▒" * (20 - (progress_percent // 5)) + "]"
            
            minutes = elapsed_seconds // 60
            seconds = elapsed_seconds % 60
            time_display = f"{minutes:02d}:{seconds:02d}"
            
            rem_minutes = remaining_seconds // 60
            rem_seconds = remaining_seconds % 60
            rem_display = f"{rem_minutes:02d}:{rem_seconds:02d}"
            
            # REAL-TIME STATUS UPDATE
            status_text = (
                f"📱 **Real-time OTP Monitoring**\n"
                f"🔢 Number: `{phone}`\n"
                f"⏰ Time: {time_display} | Remaining: {rem_display}\n"                
                f"🔄 Attempt: {check_count} | 🔍 Checking...\n\n"
                f"📊 {progress_bar} {progress_percent}%\n"
            )
            
            await processing_msg.edit_text(status_text, parse_mode='Markdown')
            
            # 🔥 INSTANT OTP CHECK EVERY SECOND
            try:
                otp_response = await get_code(token, phone, website_config, device_name)
                
                if otp_response and otp_response.get("code") == 1:
                    otp = extract_otp_from_response(otp_response)
                    
                    if otp:
                        current_otp_processes[process_key]['message_sent'] = True
                        final_elapsed = int(time.time() - start_time)
                        final_minutes = final_elapsed // 60
                        final_seconds = final_elapsed % 60
                        final_time_display = f"{final_minutes:02d}:{final_seconds:02d}"
                        
                        # INSTANT SUCCESS RESPONSE
                        await processing_msg.edit_text(
                            f"🎉 **OTP RECEIVED SUCCESSFULLY!**\n\n"
                            f"📱 Number: `{phone}`\n"
                            f"🔐 OTP Code: `{otp}`\n"
                            f"⏱️ Time: {final_time_display}\n"
                            f"🔄 Attempt: {check_count}\n"
                            f"✅ **PROCESS COMPLETED**",
                            parse_mode='Markdown'
                        )
                        logger.info(f"🎯 OTP INSTANTLY FOUND for {phone} in {final_time_display}")
                        return
                        
            except Exception as api_error:
                logger.warning(f"API attempt {check_count} failed: {api_error}")
                # Continue despite errors
            
            # Wait exactly 1 second
            await asyncio.sleep(1)
        
        # Timeout
        final_elapsed = int(time.time() - start_time)
        await processing_msg.edit_text(
            f"⏰ **TIME OUT**\n\n"
            f"📱 Number: `{phone}`\n"
            f"⏱️ Duration: {final_elapsed}s\n"
            f"🔄 Attempts: {check_count}\n"
            f"❌ No OTP received\n"
            f"💡 Please try again",
            parse_mode='Markdown'
        )
    
    except Exception as e:
        logger.error(f"Error: {e}")
        try:
            await processing_msg.edit_text(f"❌ System error for {phone}")
        except:
            pass
    
    finally:
        if process_key in current_otp_processes:
            current_otp_processes.pop(process_key)

def extract_otp_from_response(otp_response):
    """Extract OTP from various response formats"""
    try:
        otp = None
        data_field = otp_response.get("data", {})
        
        if isinstance(data_field, dict):
            otp = data_field.get("code")
        elif isinstance(data_field, str) and data_field.isdigit() and len(data_field) == 6:
            otp = data_field
        else:
            msg = otp_response.get("msg", "")
            code_match = re.search(r'\b\d{4,6}\b', msg)
            if code_match:
                otp = code_match.group(0)
        
        return otp
    except Exception as e:
        logger.error(f"Error extracting OTP: {e}")
        return None


def count_active_processes(user_id):
    """Count active OTP processes for a user"""
    try:
        count = 0
        for key in list(current_otp_processes.keys()):
            if key.startswith(f"{user_id}_") and current_otp_processes[key].get('active', False):
                count += 1
        return count
    except Exception as e:
        logger.error(f"Error counting processes: {e}")
        return 0


async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = update.message.from_user.id
        selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
        
        # Cleanup all processes for this user
        cancelled_count = 0
        for key in list(current_otp_processes.keys()):
            if key.startswith(f"{user_id}_"):
                current_otp_processes[key]['active'] = False
                cancelled_count += 1
        
        context.user_data.clear()
        context.user_data['selected_website'] = selected_website
        await update.message.reply_text(
            f"✅ All processes stopped. {cancelled_count} processes cancelled.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
    except Exception as e:
        logger.error(f"Error in stop command: {e}")
        await update.message.reply_text(
            f"❌ Error stopping processes: {str(e)}"
        )


# Error handler for the bot
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors in the bot."""
    logger.error(f"Bot error: {context.error}", exc_info=context.error)
    
    try:
        if update and update.message:
            await update.message.reply_text(
                "❌ A system error occurred. Please try again later.",
                reply_markup=get_main_keyboard(DEFAULT_SELECTED_WEBSITE, update.message.from_user.id)
            )
    except Exception as e:
        logger.error(f"Error in error_handler: {e}")

async def link_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    logger.info(f"Link command triggered by user {user_id} for {selected_website}")
    tokens = load_tokens()
    device_name = str(user_id)
    if not device_manager.exists(device_name):
        await update.message.reply_text(
            "❌ Please set user agent first using 'Set User Agent'.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    if str(user_id) not in tokens or selected_website not in tokens[str(user_id)] or 'main' not in tokens[str(user_id)][selected_website]:
        await update.message.reply_text(
            f"❌ {selected_website} account not found. Please login first with 'Log in Account'",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    context.user_data['state'] = 'awaiting_phone'
    await update.message.reply_text(
        "📱 Send your Canada WhatsApp number. Send /stop to exit.",
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def phone_list_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    website_config = WEBSITE_CONFIGS[selected_website]
    device_name = str(user_id)
    if not device_manager.exists(device_name):
        await update.message.reply_text("❌ Please set user agent first using 'Set User Agent'.", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    logger.info(f"Phone list command triggered by user {user_id} for {selected_website}")
    tokens = load_tokens()
    if str(user_id) not in tokens or selected_website not in tokens[str(user_id)] or 'main' not in tokens[str(user_id)][selected_website]:
        await update.message.reply_text(
            f"❌ {selected_website} account not found. Please login first with 'Log in Account'",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    token = tokens[str(user_id)][selected_website]['main']
    await update.message.reply_text(f"⏳ Fetching phone list for {selected_website} account...")
    result = await get_phone_list(token, 'main', website_config, device_name)
    await update.message.reply_text(result, reply_markup=get_main_keyboard(selected_website, user_id))

async def task_statistics_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    website_config = WEBSITE_CONFIGS[selected_website]
    device_name = str(user_id)
    if not device_manager.exists(device_name):
        await update.message.reply_text("❌ Please set user agent first using 'Set User Agent'.", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    logger.info(f"Task statistics command triggered by user {user_id} for {selected_website}")
    tokens = load_tokens()
    if str(user_id) not in tokens or selected_website not in tokens[str(user_id)] or 'main' not in tokens[str(user_id)][selected_website]:
        await update.message.reply_text(
            f"❌ {selected_website} account not found. Please login first with 'Log in Account'",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    token = tokens[str(user_id)][selected_website]['main']
    await update.message.reply_text(f"⏳ Fetching task statistics for {selected_website}...")
    result = await get_task_statistics(token, website_config, device_name)
    await update.message.reply_text(result, reply_markup=get_main_keyboard(selected_website, user_id))

async def bulk_send_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    website_config = WEBSITE_CONFIGS[selected_website]
    device_name = str(user_id)
    if not device_manager.exists(device_name):
        await update.message.reply_text("❌ Please set user agent first using 'Set User Agent'.", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    logger.info(f"Bulk send command triggered by user {user_id} for {selected_website}")
    tokens = load_tokens()
    if str(user_id) not in tokens or selected_website not in tokens[str(user_id)] or 'main' not in tokens[str(user_id)][selected_website]:
        await update.message.reply_text(
            f"❌ {selected_website} account not found. Please login first with 'Log in Account'",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    token = tokens[str(user_id)][selected_website]['main']
    await update.message.reply_text(f"🚀 Starting bulk send for {selected_website}...")
    result = await bulk_send_messages(token, website_config, device_name)
    await update.message.reply_text(result, reply_markup=get_main_keyboard(selected_website, user_id))

async def get_pagination_keyboard(current_page, total_pages, user_id):
    buttons = []
    if current_page > 1:
        buttons.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"regs_page_{current_page-1}_{user_id}"))
    if current_page < total_pages:
        buttons.append(InlineKeyboardButton("Next ➡️", callback_data=f"regs_page_{current_page+1}_{user_id}"))
    return InlineKeyboardMarkup([buttons]) if buttons else None

async def get_registrations(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if not os.path.exists(REGISTRATION_FILE):
        await update.message.reply_text(
            "কোনো রেজিস্ট্রেশন ডেটা পাওয়া যায়নি।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return

    with open(REGISTRATION_FILE, 'r') as f:
        content = f.read()

    entries = re.split(r'\n\s*\n', content.strip())
    valid_entries = [entry for entry in entries if entry.strip() and re.match(r'^\d+\.', entry)]
    
    entries_per_page = 10
    total_entries = len(valid_entries)
    total_pages = (total_entries + entries_per_page - 1) // entries_per_page
    current_page = context.user_data.get('regs_page', 1)
    
    if current_page < 1:
        current_page = 1
    elif current_page > total_pages:
        current_page = total_pages
    
    context.user_data['regs_page'] = current_page
    
    start_idx = (current_page - 1) * entries_per_page
    end_idx = min(start_idx + entries_per_page, total_entries)
    
    now = get_bd_time()
    output = []
    
    for entry in valid_entries[start_idx:end_idx]:
        lines = entry.split('\n')
        first_line = lines[0].strip()
        match = re.match(r'(\d+)\.\s*Date:\s*(\d{4}-\d{2}-\d{2})\s*Time:\s*(\d{2}:\d{2}:\d{2})', first_line)
        if not match:
            continue
        num = match.group(1)
        date_str = match.group(2)
        time_str = match.group(3)
        try:
            reg_time = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) + timedelta(hours=6)
        except ValueError:
            continue
        age = now - reg_time
        age_days = age.days
        age_hours = age.seconds // 3600  # দিন + ঘন্টা দেখাচ্ছে
        used = "no"
        for line in lines:
            if line.strip().startswith("Used:"):
                used = line.strip().split(":", 1)[1].strip().lower()
                break
        data_lines = []
        for line in lines:
            if line.strip().startswith("Used:"):
                emoji = "🚫" if used == "no" else "⛔️"
                data_lines.append(f"   Used: {used} {emoji}")
            else:
                data_lines.append(line)
        if used == "no":
            days_emoji = "✅️" if age_days >= 3 else "🔄"
            data_lines.append(f"   {age_days} days {age_hours} hours old {days_emoji}")
        entry_text = '\n'.join(data_lines)
        output.append(f"```{entry_text}```")

    full_output = '\n\n'.join(output) if output else "কোনো বৈধ রেজিস্ট্রেশন ডেটা পাওয়া যায়নি।"
    
    full_output = f"📄 পেজ {current_page}/{total_pages} ({total_entries}টি এন্ট্রি)\n\n{full_output}"
    
    await update.message.reply_text(
        full_output,
        parse_mode='Markdown',
        reply_markup=await get_pagination_keyboard(current_page, total_pages, user_id)
    )

async def handle_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()  # Always answer callback queries first
    
    user_id = query.from_user.id
    data = query.data
    
    if data.startswith("regs_page_"):
        try:
            _, _, page_str, query_user_id = data.split("_")
            if int(query_user_id) != user_id:
                await query.answer("এই বাটনটি আপনার জন্য নয়।")
                return
            
            new_page = int(page_str)
            context.user_data['regs_page'] = new_page
            
            # Reuse the same logic from get_registrations
            if not os.path.exists(REGISTRATION_FILE):
                await query.edit_message_text("কোনো রেজিস্ট্রেশন ডেটা পাওয়া যায়নি।")
                return

            with open(REGISTRATION_FILE, 'r', encoding='utf-8') as f:
                content = f.read()

            entries = re.split(r'\n\s*\n', content.strip())
            valid_entries = [entry for entry in entries if entry.strip() and re.match(r'^\d+\.', entry)]
            
            entries_per_page = 10
            total_entries = len(valid_entries)
            total_pages = max(1, (total_entries + entries_per_page - 1) // entries_per_page)
            new_page = min(max(1, new_page), total_pages)
            
            start_idx = (new_page - 1) * entries_per_page
            end_idx = min(start_idx + entries_per_page, total_entries)
            
            now = get_bd_time()
            output = []
            
            for entry in valid_entries[start_idx:end_idx]:
                lines = [line.strip() for line in entry.split('\n') if line.strip()]
                if not lines:
                    continue
                    
                first_line = lines[0]
                match = re.match(r'(\d+)\.\s*Date:\s*(\d{4}-\d{2}-\d{2})\s*Time:\s*(\d{2}:\d{2}:\d{2})', first_line)
                if not match:
                    continue
                    
                num = match.group(1)
                date_str = match.group(2)
                time_str = match.group(3)
                
                try:
                    reg_time = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) + timedelta(hours=6)
                    age = now - reg_time
                    age_days = age.days
                    age_hours = age.seconds // 3600
                except ValueError:
                    continue
                    
                used = "no"
                for line in lines:
                    if line.lower().startswith("used:"):
                        used = line.split(":", 1)[1].strip().lower()
                        break
                        
                entry_text = []
                for line in lines:
                    if not line.lower().startswith("used:"):
                        entry_text.append(line)
                        
                if used == "no":
                    days_text = f"{age_days} দিন {age_hours} ঘন্টা"
                    if age_days >= 3:
                        entry_text.append(f"   Age: {days_text} ✅️")
                    else:
                        entry_text.append(f"   Age: {days_text} 🔄")
                else:
                    entry_text.append("   Used: yes ⛔️")
                    
                # Markdown code block যোগ করুন
                output.append(f"```{'\n'.join(entry_text)}```")

            if not output:
                full_output = "কোনো বৈধ রেজিস্ট্রেশন ডেটা পাওয়া যায়নি।"
            else:
                full_output = f"📄 পেজ {new_page}/{total_pages} ({total_entries}টি এন্ট্রি)\n\n" + "\n\n".join(output)
            
            await query.edit_message_text(
                full_output,
                parse_mode='Markdown',
                reply_markup=await get_pagination_keyboard(new_page, total_pages, user_id))
                
        except Exception as e:
            logger.error(f"Error in callback handler: {str(e)}")
            await query.edit_message_text("❌ পেজ লোড করতে সমস্যা হয়েছে।")

async def mark_used(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    if not context.args:
        await update.message.reply_text("Usage: /markused <entry number>", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    try:
        num = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid number.", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    if not os.path.exists(REGISTRATION_FILE):
        await update.message.reply_text("No registration data.", reply_markup=get_main_keyboard(selected_website, user_id))
        return

    with open(REGISTRATION_FILE, 'r') as f:
        content = f.read()

    entries = re.split(r'\n\s*\n', content.strip())
    found = False
    new_entries = []

    for entry in entries:
        if not entry.strip():
            new_entries.append(entry)
            continue
        lines = entry.split('\n')
        first_line = lines[0].strip()
        match = re.match(r'(\d+)\.', first_line)
        if match and int(match.group(1)) == num:
            found = True
            has_used = False
            for i, line in enumerate(lines):
                if line.strip().startswith("Used:"):
                    lines[i] = "   Used: yes ✅️"
                    has_used = True
                elif line.strip().startswith(f"   {match.group(1)} days old"):
                    lines[i] = ""  # Remove age line if present
            if not has_used:
                lines.append("   Used: yes ✅️")
            new_entries.append('\n'.join([line for line in lines if line.strip()]))
        else:
            new_entries.append(entry)

    if not found:
        await update.message.reply_text(f"No entry found with number {num}.", reply_markup=get_main_keyboard(selected_website, user_id))
        return

    with open(REGISTRATION_FILE, 'w') as f:
        f.write('\n\n'.join(new_entries) + '\n')

    await update.message.reply_text(f"Entry {num} marked as used.", reply_markup=get_main_keyboard(selected_website, user_id))

async def delete_used(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    if not os.path.exists(REGISTRATION_FILE):
        await update.message.reply_text("No registration data.", reply_markup=get_main_keyboard(selected_website, user_id))
        return

    with open(REGISTRATION_FILE, 'r') as f:
        content = f.read()

    entries = re.split(r'\n\s*\n', content.strip())
    kept_entries = []
    count = 0

    for entry in entries:
        if not entry.strip():
            continue
        if "Used: yes" in entry:
            continue
        kept_entries.append(entry)

    if not kept_entries:
        with open(REGISTRATION_FILE, 'w') as f:
            f.write('')
        await update.message.reply_text("All used entries deleted. No entries left.", reply_markup=get_main_keyboard(selected_website, user_id))
        return

    renumbered_entries = []
    for idx, entry in enumerate(kept_entries, 1):
        lines = entry.split('\n')
        first_line = lines[0].strip()
        match = re.match(r'(\d+)\.', first_line)
        if match:
            lines[0] = lines[0].replace(f"{match.group(1)}.", f"{idx}.")
        renumbered_entries.append('\n'.join(lines))

    with open(REGISTRATION_FILE, 'w') as f:
        f.write('\n\n'.join(renumbered_entries) + '\n')

    deleted_count = len(entries) - len(kept_entries)
    await update.message.reply_text(f"{deleted_count} used entries deleted. {len(renumbered_entries)} entries remain.", reply_markup=get_main_keyboard(selected_website, user_id))

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    context.user_data.clear()
    context.user_data['selected_website'] = selected_website
    await update.message.reply_text(
        "✅ Process stopped. Select an option to continue.",
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id if update.message else "Unknown"
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    try:
        raise context.error
    except NetworkError:
        logger.error(f"Network error for user {user_id}: {context.error}")
        if update.message:
            await update.message.reply_text(
                "❌ Network error occurred. Please try again later.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
    except BadRequest as e:
        logger.error(f"Bad request error for user {user_id}: {str(e)}")
        if update.message:
            await update.message.reply_text(
                f"❌ Bad request: {str(e)}",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
    except Exception as e:
        logger.error(f"Unexpected error for user {user_id}: {str(e)}")
        if update.message:
            await update.message.reply_text(
                f"❌ An unexpected error occurred: {str(e)}",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )

def main():
    # Start Flask server in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logger.info("Flask server started in background thread")
    
    # Start Telegram bot
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("login", login_command))
    app.add_handler(CommandHandler("regs", get_registrations))
    app.add_handler(CommandHandler("markused", mark_used))
    app.add_handler(CommandHandler("deleteused", delete_used))
    app.add_handler(CommandHandler("stop", stop))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(CallbackQueryHandler(handle_callback_query))
    app.add_error_handler(error_handler)

    logger.info("Bot is starting...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()

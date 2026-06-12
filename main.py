#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
E2EE 端到端聊天室 - V6 (Space Jump Dashboard 版)
[战术配置]: 默认启动即上锁。仅允许 TMP_ROOM 生成的合法通道接入。
[光速注入]: 启动时对 chat.html 进行 O(1) 预编译缓存，验证通过后采用 Binary 极速推送。
[独立死神]: 废除 server.conf 全局倒计时，由前端控制台为每个临时房间指定独立安全存活时间。
[战术管控]: 废除 URL 传参触发紧急控制，全局熔断与空间跳跃全部迁移至后台 Dashboard 鉴权 API。
[商业化]: 引入 Token 经济系统，支持买家专属哈希路径访问及按次扣费 (基于 Supabase 云端引擎)。
"""

import os
import sys
import time
import threading
import uvicorn
import asyncio
import hashlib
import binascii
import hmac
import uuid
import platform
import json
import string
import random
import base64
from typing import Dict, List, Set, Any, Optional
from collections import deque
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header, Body, Request
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

# === 商业化：Supabase 数据库引入 ===
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv() # 加载 .env 环境变量文件

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if SUPABASE_URL and SUPABASE_KEY:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ [Database] 成功连接至 Supabase 云端数据库")
else:
    supabase = None
    print("⚠️ [系统警告] 缺失 SUPABASE_URL 或 SUPABASE_KEY，Token 计费系统将无法启动！")

# === 运行时全局变量 ===
CONFIG_FILE = "server.conf"

BIND_IP: str = ""
SERVER_PORT: int = 0
REVERSE_PROXY_MODE: bool = False
SSL_CERT_PATH: str = ""
SSL_KEY_PATH: str = ""

ADMIN_KEY_HASH: Optional[str] = None
IFRAME_URL: str = ""                        # 伪装站点 URL

GLOBAL_CHAT_ENABLED: bool = True            # 全局聊天开关
HALT_WHITELIST_UIDS: Set[str] = set()       # 熔断期间允许重连的战友白名单快照

HISTORY_MAX: int = 0
IMAGE_MAX: int = 0
VOICE_MAX: int = 0
MAX_CLIENTS: int = 0
SESSION_TIMEOUT: int = 0

# 仅作为未传参时的内存兜底
SAFE_TIME: int = 180                        
# 房间创建后如果一直没有真实用户进入，最多保留 1200 秒，避免遗忘房间长期占用内存
UNUSED_ROOM_TTL: int = 1200
ROOM_SAFE_TIME_MIN: int = 30
ROOM_SAFE_TIME_MAX: int = 1200

BANNED_IDS: Set[str] = set()
BANNED_IPS: Set[str] = set()
SESSION_STORE: Dict[str, float] = {}
MAIN_LOOP = None

# 【提速优化】UI 预编译缓存池
CHAT_HTML_B64_CACHE: str = ""
CHAT_HTML_RAW_CACHE: bytes = b"" # 【新增】二进制缓存池，实现零编解码下发

# === 动态加密房间状态机 (默认启动即上锁防扫描) ===
DEFAULT_ROOM_LOCK: bool = True
# 记录临时房间： { room_hash: {"created_at": float, "last_active_time": float, "timer_started": bool, "pwd": str, "safe_time": int, "owner": str} }
DYNAMIC_ROOMS: Dict[str, Dict[str, Any]] = {}

# === 配置文件管理模块 ===

def detect_binary_packet_type(blob: bytes) -> str:
    try:
        if len(blob) < 4:
            return "image"
        header_len = int.from_bytes(blob[:4], byteorder="little", signed=False)
        if header_len <= 0 or header_len > 8192 or len(blob) < 4 + header_len:
            return "image"
        header = json.loads(blob[4:4 + header_len].decode("utf-8"))
        return "voice" if header.get("type") == "audio" else "image"
    except Exception:
        return "image"

def clamp_room_safe_time(value: Any) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = SAFE_TIME
    return max(ROOM_SAFE_TIME_MIN, min(ROOM_SAFE_TIME_MAX, parsed))

def load_config():
    """运维核心：严格从文件加载配置，废弃无用的应急 Key"""
    global SERVER_PORT, BIND_IP, SSL_CERT_PATH, SSL_KEY_PATH, ADMIN_KEY_HASH
    global HISTORY_MAX, IMAGE_MAX, VOICE_MAX, MAX_CLIENTS, SESSION_TIMEOUT, REVERSE_PROXY_MODE
    global IFRAME_URL

    # 初始化/清理状态
    ADMIN_KEY_HASH = None
    IFRAME_URL = ""
    VOICE_MAX = 25
    BANNED_IDS.clear()
    BANNED_IPS.clear()
    HALT_WHITELIST_UIDS.clear()

    # 1. 模板生成逻辑：仅在文件不存在时执行一次
    if not os.path.exists(CONFIG_FILE):
        print(f"⚠️ 配置文件 {CONFIG_FILE} 不存在，正在生成标准模板...")
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("BIND_IP=0.0.0.0\nPORT=888\nREVERSE_PROXY=false\n")
                f.write("HISTORY_MAX=25\nIMAGE_MAX=25\nVOICE_MAX=25\n")
                f.write("MAX_CLIENTS=500\nSESSION_TIMEOUT=7200\n")
                f.write("SSL_CERT=\nSSL_KEY=\nadmin_key=\niframe=https://www.baidu.com\nbanned=\nbanned_ips=\n")
            print("✅ 模板生成完毕，首次启动将以模板默认值运行。请稍后根据需要修改。")
        except Exception as e:
            print(f"❌ 无法创建配置文件，启动中止: {e}")
            sys.exit(1)

    # 2. 严格读取逻辑
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    key, value = key.strip().lower(), value.strip()
                    
                    if key == 'port': 
                        SERVER_PORT = int(value)
                    elif key == 'reverse_proxy': 
                        REVERSE_PROXY_MODE = (value == 'true')
                    elif key == 'history_max': 
                        HISTORY_MAX = int(value)
                    elif key == 'image_max': 
                        IMAGE_MAX = int(value)
                    elif key == 'voice_max':
                        VOICE_MAX = int(value)
                    elif key == 'max_clients': 
                        MAX_CLIENTS = int(value)
                    elif key == 'session_timeout': 
                        SESSION_TIMEOUT = int(value)
                    elif key == 'bind_ip': 
                        BIND_IP = value
                    elif key == 'ssl_cert': 
                        SSL_CERT_PATH = value
                    elif key == 'ssl_key': 
                        SSL_KEY_PATH = value
                    elif key == 'admin_key':
                        if value:
                            ADMIN_KEY_HASH = value
                            if '$' not in value: 
                                print(f" -> [严重警告] 监测到 admin_key 明文！请重置！")
                    elif key == 'iframe':
                        if value: IFRAME_URL = value
                    elif key == 'banned':
                        if value: 
                            [BANNED_IDS.add(x.strip()) for x in value.split('|') if x.strip()]
                    elif key == 'banned_ips':
                        if value: 
                            [BANNED_IPS.add(x.strip()) for x in value.split('|') if x.strip()]
        
        # 3. 严格非空校验
        if not BIND_IP or not SERVER_PORT:
            raise ValueError("配置项 BIND_IP 和 PORT 不能为空！")
        if HISTORY_MAX <= 0 or IMAGE_MAX <= 0 or VOICE_MAX <= 0 or MAX_CLIENTS <= 0:
            raise ValueError("容量配置项必须大于0！")

        proxy_status = "开启" if REVERSE_PROXY_MODE else "关闭"
        print(f"✅ 系统配置已加载: {BIND_IP}:{SERVER_PORT} | 反代模式: {proxy_status} | 在线阈值: {MAX_CLIENTS}")

    except Exception as e:
        print(f"❌ 严格模式阻断：读取配置文件失败或格式错误: {e}")
        sys.exit(1)

def update_config_file():
    """增强版配置回写：保护所有配置项不被擦除"""
    try:
        new_lines = []
        config_map = {
            'bind_ip': BIND_IP,
            'port': str(SERVER_PORT),
            'reverse_proxy': 'true' if REVERSE_PROXY_MODE else 'false',
            'history_max': str(HISTORY_MAX),
            'image_max': str(IMAGE_MAX),
            'voice_max': str(VOICE_MAX),
            'max_clients': str(MAX_CLIENTS),
            'session_timeout': str(SESSION_TIMEOUT),
            'iframe': IFRAME_URL,
            'banned': "|".join(BANNED_IDS),
            'banned_ips': "|".join(BANNED_IPS),
            'ssl_cert': SSL_CERT_PATH,
            'ssl_key': SSL_KEY_PATH,
            'admin_key': ADMIN_KEY_HASH if ADMIN_KEY_HASH else ""
        }
        
        found_keys = set()
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                stripped = line.strip().lower()
                matched = False
                for k in config_map.keys():
                    if stripped.startswith(f"{k}="):
                        new_lines.append(f"{k.upper()}={config_map[k]}\n")
                        found_keys.add(k)
                        matched = True
                        break
                if not matched:
                    new_lines.append(line)
        
        # 补全缺失项
        for k, v in config_map.items():
            if k not in found_keys:
                new_lines.append(f"{k.upper()}={v}\n")

        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

    except Exception as e:
        print(f"❌ 写入配置文件失败: {e}")

def load_chat_html():
    """【提速重构】启动时直接完成 O(1) 的 Base64 预编译缓存与二进制缓存"""
    global CHAT_HTML_B64_CACHE, CHAT_HTML_RAW_CACHE
    try:
        if os.path.exists("chat.html"):
            with open("chat.html", "r", encoding="utf-8") as f:
                raw_html = f.read()
            # 预编译为 Base64 (保留备用)
            CHAT_HTML_B64_CACHE = base64.b64encode(raw_html.encode('utf-8')).decode('utf-8')
            # 【方案B】预编译为原始二进制
            CHAT_HTML_RAW_CACHE = raw_html.encode('utf-8')
            print("✅ 真实聊天室源码 (chat.html) 已预编译并缓存至内存池，O(1) 闪电下发就绪。")
        else:
            print("⚠️ 警告: 找不到 chat.html！内存注入功能将失效，请确保文件存在。")
    except Exception as e:
        print(f"❌ 读取 chat.html 失败: {e}")

load_config()
load_chat_html()

# === 异步独立死神机制 ===
async def room_reaper():
    print("💀 闲置时间死神机制已激活 (按最后活跃时间精准执行生命终结)")
    while True:
        try:
            await asyncio.sleep(5) 
            now = time.time()
            to_delete = []
            
            # 扫描动态房间池
            for room_hash, info in list(DYNAMIC_ROOMS.items()):
                if not info.get('timer_started', False):
                    if (now - info.get('created_at', now)) > UNUSED_ROOM_TTL:
                        to_delete.append(room_hash)
                    continue

                # 读取各房间自己独立的 safe_time
                room_safe_time = info.get('safe_time', SAFE_TIME)
                
                # 【第一处核心修改】：切回 last_active_time (闲置时间判定)
                # 这样买家发消息重置 last_active_time 后，房间寿命就会回满
                if (now - info['last_active_time']) > room_safe_time:
                    to_delete.append(room_hash)
            
            for room_hash in to_delete:
                room_info = DYNAMIC_ROOMS.get(room_hash, {})
                was_never_used = not room_info.get('timer_started', False)

                # 清退所有在场人员
                if room_hash in manager.rooms:
                    users = list(manager.rooms[room_hash]['users'])
                    for ws in users:
                        try:
                            if IFRAME_URL: 
                                await ws.send_text(f"SYS_CMD:IFRAME:{IFRAME_URL}")
                            else: 
                                await ws.send_text("SYS_ERR:⚠️ 房间存活时间已尽，通道已被死神抹杀。")
                            await ws.close()
                        except: pass
                    
                    # 使用 pop 安全回收连接池，避免 KeyError
                    manager.rooms.pop(room_hash, None)
                
                # 安全回收内存
                DYNAMIC_ROOMS.pop(room_hash, None)
                if was_never_used:
                    print(f"💀 [DEATH_REAPER] 未使用临时通道超过 {UNUSED_ROOM_TTL}s，已自动回收。")
                else:
                    print(f"💀 [DEATH_REAPER] 临时通道寿命耗尽，已被死神彻底抹除。")
                
        except Exception as e:
            # 全局异常捕获，确保背景任务永不崩溃
            print(f"⚠️ [DEATH_REAPER] 死神机制发生异常，已拦截: {e}")

# === FastAPI 生命周期管理 ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    global MAIN_LOOP
    MAIN_LOOP = asyncio.get_running_loop()
    print("✅ 事件循环已捕获 (Threadsafe Ready).")
    
    # 启动房间死神任务
    asyncio.create_task(room_reaper())
    yield

# === FastAPI 应用初始化 ===
app = FastAPI(lifespan=lifespan)

# === 连接管理器 ===
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.rooms: Dict[str, Dict[str, Any]] = {}
        self.client_stats: Dict[WebSocket, Dict[str, Any]] = {}
        self.msg_total_count = 0
        self.start_timestamp = time.time()

    async def connect(self, websocket: WebSocket, client_ip: str):
        if len(self.active_connections) >= MAX_CLIENTS:
            await websocket.accept()
            await websocket.send_text("SYS_ERR:服务器满员")
            await websocket.close()
            return False

        await websocket.accept()
        self.active_connections.append(websocket)

        self.client_stats[websocket] = {
            'count': 0, 
            'start_time': time.time(), 
            'muted_until': 0,
            'room': None, 
            'ip': client_ip, 
            'uid': None, 
            'joined_at': time.time(),
            'device_info': {}
        }
        return True

    def disconnect(self, websocket: WebSocket):
        room_id = None
        if websocket in self.client_stats:
            room_id = self.client_stats[websocket].get('room')
            del self.client_stats[websocket]
        
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            
        if room_id and room_id in self.rooms:
            if websocket in self.rooms[room_id]['users']:
                self.rooms[room_id]['users'].discard(websocket)
            if not self.rooms[room_id]['users']:
                del self.rooms[room_id]

    async def join_room(self, websocket: WebSocket, room_id: str, user_id: str):
        if websocket in self.client_stats:
            old_room = self.client_stats[websocket].get('room')
            if old_room and old_room in self.rooms:
                 self.rooms[old_room]['users'].discard(websocket)
            self.client_stats[websocket]['room'] = room_id
            self.client_stats[websocket]['uid'] = user_id

        if room_id not in self.rooms:
            self.rooms[room_id] = {
                'txt': deque(maxlen=HISTORY_MAX),
                'img': deque(maxlen=IMAGE_MAX),
                'voice': deque(maxlen=VOICE_MAX),
                'users': set()
            }

        self.rooms[room_id]['users'].add(websocket)

        if room_id in DYNAMIC_ROOMS and user_id != "BOOTSTRAP_NODE":
            room_info = DYNAMIC_ROOMS[room_id]
            if not room_info.get('timer_started', False):
                room_info['timer_started'] = True
                room_info['last_active_time'] = time.time()
                print(f"⏱️ [ROOM_TIMER] 首位用户进入临时通道，闲置倒计时已启动: {room_info.get('pwd', room_id)}")

        try:
            r_data = self.rooms[room_id]
            for msg in r_data['txt']: 
                await websocket.send_text(msg)
            for img_data in r_data['img']:
                if isinstance(img_data, bytes): 
                    await websocket.send_bytes(img_data)
            for voice_data in r_data.get('voice', []):
                if isinstance(voice_data, bytes):
                    await websocket.send_bytes(voice_data)
        except: 
            pass

    async def broadcast(self, message: Any, room_id: str, sender: WebSocket):
        if room_id not in self.rooms: 
            return
            
        target_sockets = self.rooms[room_id]['users'].copy()
        is_binary = isinstance(message, bytes)
        
        # 收集合法目标:过滤封禁 + 二进制不 echo 给 sender
        targets = []
        for connection in target_sockets:
            if is_binary and connection is sender:
                continue
            c_stats = self.client_stats.get(connection)
            if c_stats and c_stats.get('uid') in BANNED_IDS: 
                continue
            if c_stats and c_stats.get('ip') in BANNED_IPS: 
                continue
            targets.append(connection)
        
        if not targets:
            return
        
        if is_binary:
            coros = [c.send_bytes(message) for c in targets]
        else:
            coros = [c.send_text(message) for c in targets]
        await asyncio.gather(*coros, return_exceptions=True)

    def check_rate_limit(self, websocket: WebSocket) -> tuple[bool, str]:
        now = time.time()
        stats = self.client_stats.get(websocket)
        if not stats: 
            return True, ""
            
        if now < stats['muted_until']:
            return False, f"SYS_ERR:🚫 你被禁言中，剩余 {int(stats['muted_until'] - now) + 1} 秒"
            
        if now - stats['start_time'] > 1.0:
            stats['count'] = 0
            stats['start_time'] = now
            
        stats['count'] += 1
        if stats['count'] > 4:
            stats['muted_until'] = now + 5.0
            return False, "SYS_ERR:⚠️ 发送太快！已被禁言 5 秒。"
            
        return True, ""

    def save_message(self, room_id: str, message: Any, binary_type: str = "image"):
        self.msg_total_count += 1
        if room_id not in self.rooms: 
            return
        if isinstance(message, bytes):
            if binary_type == "voice":
                self.rooms[room_id].setdefault('voice', deque(maxlen=VOICE_MAX)).append(message)
            else:
                self.rooms[room_id]['img'].append(message)
        else: 
            self.rooms[room_id]['txt'].append(message)

    async def notify_ban_status(self, target_ids: List[str], is_ban: bool):
        count = 0
        for ws, stats in self.client_stats.items():
            if stats.get('uid') in target_ids:
                count += 1
                try:
                    if is_ban: 
                        await ws.send_text("SYS_ERR:管理员讨厌你 你被ban了 | The admin hates you. You've been banned.")
                    else: 
                        await ws.send_text("SYS_CMD:RELOAD")
                except: 
                    pass
        return count

    async def notify_ip_ban_status(self, target_ips: List[str], is_ban: bool):
        count = 0
        for ws, stats in self.client_stats.items():
            if stats.get('ip') in target_ips:
                count += 1
                try:
                    if is_ban: 
                        await ws.send_text("SYS_ERR:🚫 Your IP has been permanently banned.")
                    else: 
                        await ws.send_text("SYS_CMD:RELOAD")
                except: 
                    pass
        return count

    def get_system_stats(self):
        user_list = []
        for ws, stats in self.client_stats.items():
            user_list.append({
                "uid": stats.get('uid') or 'Connecting...',
                "ip": stats.get('ip'),
                "room": stats.get('room') or 'N/A',
                "online_time": int(time.time() - stats.get('joined_at', 0)),
                "is_banned": stats.get('uid') in BANNED_IDS,
                "device_info": stats.get('device_info', {})
            })
        
        now = time.time()
        temp_rooms_info = []
        for room_pwd, info in DYNAMIC_ROOMS.items():
            room_safe_time = info.get('safe_time', SAFE_TIME)
            created_ts = info['created_at']
            timer_started = info.get('timer_started', False)
            last_active_ts = info['last_active_time'] if timer_started else now
            remaining_time = max(0, int(room_safe_time - (now - info['last_active_time']))) if timer_started else room_safe_time
            temp_rooms_info.append({
                "pwd": info['pwd'],
                "remaining_time": remaining_time,    
                "last_active_ts": last_active_ts,    
                "safe_time": room_safe_time,
                "timer_started": timer_started
            })

        global DEFAULT_ROOM_LOCK, GLOBAL_CHAT_ENABLED
        return {
            "uptime": int(time.time() - self.start_timestamp),
            "server_ts": now,                       
            "total_msgs": self.msg_total_count,
            "online_count": len(self.active_connections),
            "room_count": len(self.rooms),
            "banned_count": len(BANNED_IDS),
            "banned_ips_count": len(BANNED_IPS),
            "is_locked": DEFAULT_ROOM_LOCK,
            "is_halted": not GLOBAL_CHAT_ENABLED,
            "temp_rooms": temp_rooms_info,
            "users": user_list,
            "banned_ips_list": list(BANNED_IPS)
        }

manager = ConnectionManager()

# === [控制台] 输入监控线程 ===
def console_input_monitor():
    print("\n⌨️  控制台指令系统已启动 (支持 | 分割多个用户)")
    print("   命令格式: ban id1|id2  或  unban id1|id2")
    while True:
        try:
            cmd = input().strip()
            if not cmd: continue
            if cmd.startswith("ban "):
                targets = [x.strip() for x in cmd[4:].strip().split('|') if x.strip()]
                newly = []
                for tid in targets:
                    BANNED_IDS.add(tid)
                    newly.append(tid)
                if newly:
                    print(f"🚫 已添加封禁: {newly}")
                    update_config_file()
                    if MAIN_LOOP: 
                        asyncio.run_coroutine_threadsafe(manager.notify_ban_status(newly, True), MAIN_LOOP)
            elif cmd.startswith("unban "):
                targets = [x.strip() for x in cmd[6:].strip().split('|') if x.strip()]
                unban_list = []
                for tid in targets:
                    if tid in BANNED_IDS: 
                        BANNED_IDS.remove(tid)
                        unban_list.append(tid)
                if unban_list:
                    print(f"✅ 已移除封禁: {unban_list}")
                    update_config_file()
                    if MAIN_LOOP: 
                        asyncio.run_coroutine_threadsafe(manager.notify_ban_status(unban_list, False), MAIN_LOOP)
        except: 
            break

# === [核心安全模块] 验证 ===

def verify_hash_key(input_key: str, stored_hash_str: str) -> bool:
    if not stored_hash_str or '$' not in stored_hash_str:
        return False
    try:
        salt, stored_hash = stored_hash_str.split('$')
        server_calc = hashlib.sha256((salt + input_key).encode('utf-8')).hexdigest()
        return hmac.compare_digest(server_calc, stored_hash)
    except Exception:
        return False

def verify_session(token: str) -> bool:
    if not token or token not in SESSION_STORE:
        return False
    expire_time = SESSION_STORE[token]
    if time.time() > expire_time:
        del SESSION_STORE[token]
        return False
    return True

def clean_expired_sessions():
    now = time.time()
    to_del = [k for k, v in SESSION_STORE.items() if now > v]
    for k in to_del: 
        del SESSION_STORE[k]

def get_real_ip(websocket: WebSocket) -> str:
    client_ip = websocket.client.host if websocket.client else "Unknown"
    if REVERSE_PROXY_MODE:
        headers = websocket.headers
        if "x-forwarded-for" in headers:
            client_ip = headers["x-forwarded-for"].split(",")[0].strip()
        elif "x-real-ip" in headers:
            client_ip = headers["x-real-ip"].strip()
    return client_ip

# === 路由定义 ===

@app.get("/")
async def get(): 
    if not GLOBAL_CHAT_ENABLED:
        fallback = IFRAME_URL if IFRAME_URL else "https://www.baidu.com"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
            <title>Loading...</title>
            <style>
                body, html {{ margin: 0; padding: 0; height: 100%; overflow: hidden; background: #fff; }}
                iframe {{ width: 100%; height: 100%; border: none; }}
            </style>
        </head>
        <body>
            <iframe src="{fallback}"></iframe>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)
        
    return FileResponse('index.html', media_type="text/html; charset=utf-8")


@app.get("/manage/{access_path}")
def mobile_manage(access_path: str):
    if not supabase:
        return HTMLResponse("<h1>500 Server Error: Supabase Not Configured</h1>", status_code=500)
        
    try:
        response = supabase.table('buyers').select('*').eq('access_path', access_path).execute()
        
        if not response.data:
            return HTMLResponse("<h1>404 Not Found (未授权或失效的专属通道)</h1>", status_code=404)
            
        user_data = response.data[0]
        
        if os.path.exists('mobile-dashboard.html'):
            with open("mobile-dashboard.html", "r", encoding="utf-8") as f:
                html_content = f.read()
                
            html_content = html_content.replace("{{UID}}", user_data['uid'])
            html_content = html_content.replace("{{BALANCE}}", str(user_data['token_balance']))
            html_content = html_content.replace("{{COST}}", str(user_data['token_cost']))
            html_content = html_content.replace("{{ACCESS_PATH}}", user_data['access_path'])
            
            return HTMLResponse(content=html_content)
            
        return JSONResponse({"ERROR": "mobile-dashboard.html missing"}, 404)
    except Exception as e:
        print(f"⚠️ [DB Error] 数据库查询失败: {e}")
        return HTMLResponse("<h1>500 Server Error</h1>", status_code=500)


@app.get("/monitor")
async def monitor_page(request: Request):
    if not ADMIN_KEY_HASH: 
        return JSONResponse({"status": "error", "msg": "No Key Configured"}, 403)
        
    if not os.path.exists('dashboard.html'): 
        return JSONResponse({"ERROR": "dashboard.html missing"}, 404)
        
    return FileResponse('dashboard.html', media_type="text/html; charset=utf-8")

@app.post("/api/auth/login")
async def auth_login(data: dict = Body(...)):
    if not ADMIN_KEY_HASH or '$' not in ADMIN_KEY_HASH:
        raise HTTPException(403, detail="Dashboard Disabled")

    client_key = data.get("client_key")
    if not client_key:
        raise HTTPException(400, detail="Missing Authentication Key")

    if not verify_hash_key(client_key, ADMIN_KEY_HASH):
        await asyncio.sleep(1)
        raise HTTPException(401, detail="Auth Failed")

    token = str(uuid.uuid4())
    clean_expired_sessions()
    SESSION_STORE[token] = time.time() + SESSION_TIMEOUT
    return {"status": "ok", "token": token}

@app.get("/api/stats")
async def get_stats(x_session_token: Optional[str] = Header(None)):
    if not verify_session(x_session_token):
        raise HTTPException(401, detail="Invalid Session")
    return manager.get_system_stats()


@app.get("/api/buyer/info")
def api_buyer_info(access_path: str):
    if not supabase:
        raise HTTPException(500, detail="Supabase not configured")
        
    try:
        response = supabase.table('buyers').select('uid, token_balance, token_cost').eq('access_path', access_path).execute()
        if not response.data:
            raise HTTPException(401, detail="Invalid path")
            
        row = response.data[0]
        return {"uid": row['uid'], "balance": row['token_balance'], "cost": row['token_cost']}
    except Exception as e:
        print(f"⚠️ [DB Error] 数据库查询失败: {e}")
        raise HTTPException(500, detail="Database Error")


@app.post("/api/ban")
async def api_ban_user(data: dict, x_session_token: Optional[str] = Header(None)):
    if not verify_session(x_session_token):
        raise HTTPException(401, detail="Invalid Session")

    uid = data.get("target")
    if not uid: uid = data.get("uid")
    action = data.get("action")
    type_ = data.get("type")
    
    if not uid: return {"status": "error", "msg": "No Target"}

    changed = False
    if action == "ban":
        if type_ == "ip":
            if uid not in BANNED_IPS:
                BANNED_IPS.add(uid)
                changed = True
                await manager.notify_ip_ban_status([uid], True)
        else:
            if uid not in BANNED_IDS:
                BANNED_IDS.add(uid)
                changed = True
                await manager.notify_ban_status([uid], True)
                
    elif action == "unban":
        if type_ == "ip":
            if uid in BANNED_IPS:
                BANNED_IPS.remove(uid)
                changed = True
                await manager.notify_ip_ban_status([uid], False)
        else:
            if uid in BANNED_IDS:
                BANNED_IDS.remove(uid)
                changed = True
                await manager.notify_ban_status([uid], False)

    if changed: 
        update_config_file()
    return {"status": "ok"}

@app.post("/api/admin/shutdown")
async def shutdown_system_api(
    x_session_token: Optional[str] = Header(None)
):
    if not verify_session(x_session_token):
        print(f"⚠️ [Security] Shutdown attempt failed: Invalid Session")
        raise HTTPException(401, detail="Invalid Session")
    
    global GLOBAL_CHAT_ENABLED, HALT_WHITELIST_UIDS, DEFAULT_ROOM_LOCK, IFRAME_URL
    
    GLOBAL_CHAT_ENABLED = not GLOBAL_CHAT_ENABLED
    
    if not GLOBAL_CHAT_ENABLED:
        DEFAULT_ROOM_LOCK = True 
        HALT_WHITELIST_UIDS.clear() 
        
        count = 0
        for ws in list(manager.active_connections):
            try:
                if IFRAME_URL:
                    await ws.send_text(f"SYS_CMD:IFRAME:{IFRAME_URL}")
                else:
                    await ws.send_text("SYS_ERR:🚨 服务器已被彻底封锁。")
                await ws.close()
                count += 1
            except: pass
        
        print(f"🚨 [SYSTEM_HALT] 触发战术封锁！已向 {count} 个终端下发 IFRAME 伪装指令并强制断开。")
        return {"status": "ok", "action": "halted", "msg": f"SYSTEM_HALTED. Disguised and kicked {count} users."}
    
    else:
        print(f"✅ [SYSTEM_HALT] 战术封锁已解除，系统恢复外部接入通道 (维持锁定模式)。")
        return {"status": "ok", "action": "resumed", "msg": "SYSTEM_RESUMED. Open for external connections."}

@app.post("/api/admin/space_jump")
async def api_space_jump(data: dict = Body({}), x_session_token: Optional[str] = Header(None)):
    if not verify_session(x_session_token):
        raise HTTPException(401, detail="Invalid Session")
    
    room_safe_time = clamp_room_safe_time(data.get("safe_time", SAFE_TIME))
    
    chars = string.ascii_letters + string.digits
    new_room_pwd = ''.join(random.choice(chars) for _ in range(12))
    room_hash = hashlib.sha256(new_room_pwd.encode()).hexdigest()
    
    DYNAMIC_ROOMS.clear()
    DYNAMIC_ROOMS[room_hash] = {
        "created_at": time.time(),
        "last_active_time": time.time(), 
        "timer_started": False,
        "has_msg": False, 
        "pwd": new_room_pwd,
        "safe_time": room_safe_time,
        "owner": "admin"
    }
    
    count = 0
    for ws in list(manager.active_connections):
        try:
            await ws.send_text(f"SYS_CMD:MIGRATE:{new_room_pwd}")
            count += 1
        except:
            pass
            
    manager.rooms.clear()
    
    print(f"🌀 [EMERGENCY] 后台全体转移已触发，{count} 个终端被强行迁往新维度: {new_room_pwd} (寿命 {room_safe_time}s)")
    return {"status": "ok", "action": "space_jump_triggered", "targets_moved": count, "new_room": new_room_pwd}

@app.post("/api/admin/lock_mode")
async def api_lock_mode(data: dict = Body(...), x_session_token: Optional[str] = Header(None)):
    if not verify_session(x_session_token):
        raise HTTPException(401, detail="Invalid Session")
    
    global DEFAULT_ROOM_LOCK, IFRAME_URL
    DEFAULT_ROOM_LOCK = data.get("lock", False)
    
    if DEFAULT_ROOM_LOCK:
        count = 0
        for ws in list(manager.active_connections):
            stats = manager.client_stats.get(ws, {})
            r = stats.get('room')
            if r and r not in DYNAMIC_ROOMS:
                try:
                    if IFRAME_URL:
                        await ws.send_text(f"SYS_CMD:IFRAME:{IFRAME_URL}")
                    else:
                        await ws.send_text("SYS_ERR:🚫 空间已被锁定。")
                    await ws.close()
                    count += 1
                except: pass
        status_msg = f"已上锁 (伪装并清退了 {count} 个未授权终端)"
    else:
        status_msg = "已解锁"
        
    print(f"🔒 [MONITOR] 聊天室默认通道状态: {status_msg}")
    return {"status": "ok", "locked": DEFAULT_ROOM_LOCK}


@app.post("/api/admin/generate_room")
def api_generate_room(request: Request, data: dict = Body({}), x_session_token: Optional[str] = Header(None)):
    
    is_admin = verify_session(x_session_token)
    access_path = data.get("access_path")
    
    buyer_uid = "admin"
    new_balance = "无限"

    if not is_admin:
        if not access_path:
            print("⚠️ [安全拦截] 无效的生成请求，缺少 Token 鉴权路径。")
            raise HTTPException(401, detail="Unauthorized")
            
        if not supabase:
            raise HTTPException(500, detail="Supabase not configured")
            
        try:
            response = supabase.table('buyers').select('uid, token_balance, token_cost').eq('access_path', access_path).execute()
            
            if not response.data:
                raise HTTPException(401, detail="Invalid access path")
                
            row = response.data[0]
            buyer_uid = row['uid']
            balance = row['token_balance']
            cost = row['token_cost']
            
            if balance < cost:
                return {"status": "error", "msg": f"Token 余额不足，请充值。剩余: {balance}"}
                
            # 执行计费扣除
            new_balance = balance - cost
            supabase.table('buyers').update({'token_balance': new_balance}).eq('uid', buyer_uid).execute()
            print(f"💰 [Token 计费] 账户 {buyer_uid} 消耗 {cost} Token，剩余: {new_balance}")
            
        except Exception as e:
            print(f"⚠️ [DB Error] 数据库计费操作失败: {e}")
            raise HTTPException(500, detail="Database Error")

    # 3. 正常生成房间逻辑
    room_safe_time = clamp_room_safe_time(data.get("safe_time", SAFE_TIME))
    chars = string.ascii_letters + string.digits
    new_pwd = ''.join(random.choice(chars) for _ in range(12))
    room_hash = hashlib.sha256(new_pwd.encode()).hexdigest()
    
    DYNAMIC_ROOMS[room_hash] = {
        "created_at": time.time(),
        "last_active_time": time.time(), 
        "timer_started": False,
        "has_msg": False, 
        "pwd": new_pwd,
        "safe_time": room_safe_time,
        "owner": buyer_uid  # 记录所有者
    }
    
    print(f"🔑 [MONITOR] 分配临时通道: {new_pwd} (寿命 {room_safe_time}s, 归属: {buyer_uid})")
    return {"status": "ok", "room_pwd": new_pwd, "balance": new_balance}


# 【核心新增2】：前端实时心跳探针接口
@app.get("/api/room/time_left")
def api_room_time_left(room_pwd: str):
    """
    提供给前端控制台的实时探针。
    读取内存数据库，返回特定房间的精确剩余时间。
    """
    now = time.time()
    for room_hash, info in DYNAMIC_ROOMS.items():
        if info['pwd'] == room_pwd:
            room_safe_time = info.get('safe_time', SAFE_TIME)
            if not info.get('timer_started', False):
                remaining = max(0, int(UNUSED_ROOM_TTL - (now - info.get('created_at', now))))
                return {"status": "waiting", "remaining_time": remaining, "timer_started": False}

            # 使用 last_active_time 实时计算，精准同步死神的秒表
            remaining = max(0, int(room_safe_time - (now - info['last_active_time'])))
            return {"status": "active", "remaining_time": remaining, "timer_started": True}
            
    # 遍历字典找不到，说明房间已被死神销毁
    return {"status": "closed", "remaining_time": 0}


@app.post("/api/room/keepalive")
def api_room_keepalive(data: dict = Body({}), x_session_token: Optional[str] = Header(None)):
    room_pwd = data.get("room_pwd")
    if not room_pwd:
        raise HTTPException(400, detail="room_pwd required")

    now = time.time()
    target_hash = None
    target_info = None
    for room_hash, info in DYNAMIC_ROOMS.items():
        if info.get('pwd') == room_pwd:
            target_hash = room_hash
            target_info = info
            break

    if not target_hash or not target_info:
        return {"status": "closed", "remaining_time": 0, "timer_started": False}

    is_admin = verify_session(x_session_token)
    if not is_admin:
        access_path = data.get("access_path")
        if not access_path or not supabase:
            raise HTTPException(401, detail="Unauthorized")
        try:
            response = supabase.table('buyers').select('uid').eq('access_path', access_path).execute()
            if not response.data:
                raise HTTPException(401, detail="Invalid access path")
            buyer_uid = response.data[0]['uid']
            if target_info.get('owner') != buyer_uid:
                raise HTTPException(403, detail="Room owner mismatch")
        except HTTPException:
            raise
        except Exception as e:
            print(f"⚠️ [DB Error] 保活鉴权失败: {e}")
            raise HTTPException(500, detail="Database Error")

    room_safe_time = target_info.get('safe_time', SAFE_TIME)
    if not target_info.get('timer_started', False):
        remaining = max(0, int(UNUSED_ROOM_TTL - (now - target_info.get('created_at', now))))
        return {
            "status": "waiting",
            "remaining_time": remaining,
            "timer_started": False,
            "msg": "房间尚未开始计时"
        }

    target_info['last_active_time'] = now
    print(f"♻️ [KEEPALIVE] 临时通道倒计时已重置: {target_info.get('pwd', target_hash)} ({room_safe_time}s)")
    return {
        "status": "active",
        "remaining_time": room_safe_time,
        "timer_started": True,
        "msg": "倒计时已重置"
    }


@app.get("/static/chart.js")
async def serve_chart():
    if os.path.exists("chart.js"):
        return FileResponse("chart.js")
    raise HTTPException(status_code=404, detail="Chart.js not found")

@app.get("/static/ios-bell.mp3")
async def serve_bell():
    if os.path.exists("ios-bell.mp3"):
        return FileResponse("ios-bell.mp3", media_type="audio/mpeg")
    raise HTTPException(status_code=404, detail="Audio not found")

@app.websocket("/ws/{room}/{uid}")
@app.websocket("/")
async def websocket_endpoint(websocket: WebSocket, room: str = None, uid: str = None):
    client_ip = get_real_ip(websocket)
    
    if not GLOBAL_CHAT_ENABLED and uid:
        if uid not in HALT_WHITELIST_UIDS:
            await websocket.accept()
            if IFRAME_URL:
                await websocket.send_text(f"SYS_CMD:IFRAME:{IFRAME_URL}")
            await websocket.close()
            return

    if not await manager.connect(websocket, client_ip): 
        print(f"⛔ [连接拒绝] 访客 IP: {client_ip} 接入失败 (可能已被封禁或房间满员)")
        return
    
    mode_text = "反代穿透" if REVERSE_PROXY_MODE else "物理直连"
    print(f"📡 [终端接入] 访客 IP: {client_ip} 成功建立连接 (网络环境: {mode_text})")
    
    try:
        if client_ip in BANNED_IPS:
             await websocket.send_text("SYS_ERR:🚫 Your IP has been permanently banned.")

        if room and uid:
            global DEFAULT_ROOM_LOCK
            if DEFAULT_ROOM_LOCK and room not in DYNAMIC_ROOMS:
                if IFRAME_URL:
                    await websocket.send_text(f"SYS_CMD:IFRAME:{IFRAME_URL}")
                else:
                    await websocket.send_text("SYS_ERR:🚫 空间已被锁定或为无效的临时通道。")
                await websocket.close()
                return
            
            await websocket.send_bytes(b"SYS_CMD:INJECT:" + CHAT_HTML_RAW_CACHE)

            await manager.join_room(websocket, room, uid)
            if uid in BANNED_IDS:
                 await websocket.send_text("SYS_ERR:管理员讨厌你 你被ban了 | The admin hates you. You've been banned.")

        while True:
            payload = await websocket.receive()
            stats = manager.client_stats.get(websocket)
            current_uid = stats.get('uid') if stats else uid

            if current_uid in BANNED_IDS:
                await websocket.send_text("SYS_ERR:管理员讨厌你 你被ban了 | The admin hates you. You've been banned.")
            elif client_ip in BANNED_IPS:
                await websocket.send_text("SYS_ERR:🚫 Your IP has been permanently banned.")

            if "text" in payload:
                data = payload["text"]

                if data.startswith("PROBE:"):
                    try:
                        probe_str = data[6:]
                        probe_data = json.loads(probe_str)
                        if stats:
                            stats['device_info'] = probe_data
                    except Exception as e:
                        print(f"⚠️ [探针解析失败] IP: {client_ip} Error: {e}")
                    continue

                if data.startswith("JOIN:"):
                    try:
                        parts = data.split(":")
                        room_id = parts[1]
                        user_id = parts[2] if len(parts) > 2 else "Unknown"

                        if not GLOBAL_CHAT_ENABLED and user_id not in HALT_WHITELIST_UIDS:
                            if IFRAME_URL:
                                await websocket.send_text(f"SYS_CMD:IFRAME:{IFRAME_URL}")
                            await websocket.close()
                            return

                        if DEFAULT_ROOM_LOCK:
                            if room_id not in DYNAMIC_ROOMS:
                                if IFRAME_URL:
                                    await websocket.send_text(f"SYS_CMD:IFRAME:{IFRAME_URL}")
                                else:
                                    await websocket.send_text("SYS_ERR:🚫 空间已被锁定或为无效的临时通道。")
                                await websocket.close()
                                return

                        await websocket.send_bytes(b"SYS_CMD:INJECT:" + CHAT_HTML_RAW_CACHE)

                        await manager.join_room(websocket, room_id, user_id)
                        if user_id in BANNED_IDS:
                            await websocket.send_text("SYS_ERR:管理员讨厌你 你被ban了 | The admin hates you. You've been banned.")
                        elif client_ip in BANNED_IPS:
                            await websocket.send_text("SYS_ERR:🚫 Your IP has been permanently banned.")
                    except: pass
                    continue

                if not stats or not stats['room']: continue
                
                if current_uid in BANNED_IDS or client_ip in BANNED_IPS: continue

                allowed, err_msg = manager.check_rate_limit(websocket)
                if not allowed: await websocket.send_text(err_msg); continue

                if len(data) > 350 * 1024: await websocket.send_text("SYS_ERR:文本过大"); continue
                
                manager.save_message(stats['room'], data)
                
                if stats['room'] in DYNAMIC_ROOMS:
                    DYNAMIC_ROOMS[stats['room']]['has_msg'] = True
                    DYNAMIC_ROOMS[stats['room']]['timer_started'] = True
                    DYNAMIC_ROOMS[stats['room']]['last_active_time'] = time.time()
                    
                await manager.broadcast(data, stats['room'], websocket)

            elif "bytes" in payload:
                if current_uid in BANNED_IDS or client_ip in BANNED_IPS: continue
                blob = payload["bytes"]
                if not stats or not stats['room']: continue
                allowed, err_msg = manager.check_rate_limit(websocket)
                if not allowed: await websocket.send_text(err_msg); continue

                binary_type = detect_binary_packet_type(blob)
                max_binary_size = 2 * 1024 * 1024 if binary_type == "voice" else int(1.5 * 1024 * 1024)

                if len(blob) > max_binary_size:
                    if binary_type == "voice":
                        await websocket.send_text("SYS_ERR:语音过大 (Max 2MB)")
                        continue
                    await websocket.send_text("SYS_ERR:图片过大 (Max 1MB)")
                    continue
                    
                manager.save_message(stats['room'], blob, binary_type)
                
                if stats['room'] in DYNAMIC_ROOMS:
                    DYNAMIC_ROOMS[stats['room']]['has_msg'] = True
                    DYNAMIC_ROOMS[stats['room']]['timer_started'] = True
                    DYNAMIC_ROOMS[stats['room']]['last_active_time'] = time.time()
                    
                await manager.broadcast(blob, stats['room'], websocket)

            if payload.get("type") == "websocket.disconnect": raise WebSocketDisconnect

    except WebSocketDisconnect:
        print(f"🔌 [正常退出] 访客 IP: {client_ip} 已断开并离开聊天室。")
    except Exception as e:
        print(f"⚠️ [异常掉线] 访客 IP: {client_ip} 连接意外中断。")
    finally:
        manager.disconnect(websocket)

def run_server():
    use_ssl = False
    
    if SSL_CERT_PATH and SSL_KEY_PATH:
        if os.path.exists(SSL_CERT_PATH) and os.path.exists(SSL_KEY_PATH):
            print(f"🔒 检测到 SSL 证书，将以 HTTPS/WSS 模式启动")
            use_ssl = True
        else:
            print(f"⚠️  证书路径已配置但文件不存在，将回退到 HTTP 模式")

    config_args = {
        "app": app,
        "host": BIND_IP,
        "port": SERVER_PORT,
        "log_level": "info",
        "access_log": False,        
        "loop": "asyncio",
        "proxy_headers": False,     
        "forwarded_allow_ips": None,
        "ws_max_size": 1024 * 1024 * 50,
        "ws_ping_interval": 20,
        "ws_ping_timeout": 20
    }

    if use_ssl:
        config_args["ssl_certfile"] = SSL_CERT_PATH
        config_args["ssl_keyfile"] = SSL_KEY_PATH

    config = uvicorn.Config(**config_args)
    server = uvicorn.Server(config)
    server.run()

if __name__ == '__main__':
    print(f'🚀 Server V6 (Space Jump Dashboard 版) initializing...')
    
    if not BIND_IP or not SERVER_PORT:
        print("❌ 核心启动参数丢失，程序安全退出。")
        sys.exit(1)

    print(f'💻 OS: {platform.system()} | Host: {BIND_IP} | Port: {SERVER_PORT}')

    t_console = threading.Thread(target=console_input_monitor, daemon=True)
    t_console.start()

    try:
        run_server()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user.")
    finally:
        input("\nPress Enter to exit...")

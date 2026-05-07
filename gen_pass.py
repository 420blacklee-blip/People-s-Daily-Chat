import hashlib, os, binascii

def generate_key_string(key_name, prompt_text):
    pwd = input(f"请输入你想设置的【{prompt_text}】密码: ").strip()
    if not pwd:
        return None
    
    # 1. 前端计算模拟 (SHA256) - 这是前端登录时真正发送的 key
    client_key = hashlib.sha256(pwd.encode()).hexdigest()

    # 2. 生成随机盐 (16位Hex)
    salt = binascii.hexlify(os.urandom(8)).decode()

    # 3. 后端计算 (Salt + Client_Key 的 SHA256) - 这是存入 server.conf 的密文
    final_hash = hashlib.sha256((salt + client_key).encode()).hexdigest()
    
    config_string = f"{key_name}={salt}${final_hash}"
    return config_string

print("=== 🔐 E2EE Chatroom 态势感知密钥生成器 ===")
print("此工具将自动生成 server.conf 所需的高强度加密哈希密文！\n")

# 现在的逻辑非常干净：只需要生成控制台后台的鉴权密钥
res_admin = generate_key_string("admin_key", "态势感知控制台")

print("\n" + "=" * 70)
if res_admin:
    print("✅ [配置环节] 请将以下内容完整复制，并替换到 server.conf 文件对应的位置：\n")
    print("-" * 60)
    print(res_admin)
    print("-" * 60)
    print("\n(替换完成后，请重启后端服务使配置生效)")
else:
    print("⚠️ 未输入任何密码，未生成新密钥。")

print("=" * 70)

# === 防止 Windows 控制台双击运行闪退 ===
print("\n数据已全部输出，请确认已复制需要的内容。")
input("请按回车键 (Enter) 退出程序...")
import hashlib
import os
import binascii


ITERATIONS = 260000


def generate_key_string(key_name, prompt_text):
    pwd = input(f"请输入你想设置的【{prompt_text}】密码: ").strip()
    if not pwd:
        return None

    salt = binascii.hexlify(os.urandom(16)).decode()
    auth_key = hashlib.pbkdf2_hmac(
        "sha256",
        pwd.encode("utf-8"),
        bytes.fromhex(salt),
        ITERATIONS,
        dklen=32
    ).hex()

    return f"{key_name}=v2${salt}${ITERATIONS}${auth_key}"


print("=== E2EE Chatroom 态势感知密钥生成器 ===")
print("此工具会生成 challenge-response 登录协议使用的 PBKDF2 v2 管理密钥。\n")

res_admin = generate_key_string("admin_key", "态势感知控制台")

print("\n" + "=" * 70)
if res_admin:
    print("请将以下内容完整复制，并替换 server.conf 文件中的 admin_key 行：\n")
    print("-" * 60)
    print(res_admin)
    print("-" * 60)
    print("\n替换完成后，请重启后端服务使配置生效。")
else:
    print("未输入任何密码，未生成新密钥。")

print("=" * 70)
print("\n数据已全部输出，请确认已复制需要的内容。")
input("请按回车键 (Enter) 退出程序...")

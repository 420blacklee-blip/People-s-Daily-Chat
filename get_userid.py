#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
E2EE Node - 商业化总控后台 (Supabase 版)
用于生成买家专属链接、充值 Token、查询客户状态
"""

import os
import uuid
import string
import random
from dotenv import load_dotenv
from supabase import create_client, Client

# 1. 加载环境变量
load_dotenv()
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("❌ 错误：未找到 Supabase 配置！请确保当前目录下有 .env 文件且内容正确。")
    exit(1)

# 初始化 Supabase 客户端
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def generate_access_path(length=10):
    """生成随机的专属访问哈希路径"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def create_new_buyer():
    """功能 1：创建新买家（发卡）"""
    print("\n=== 🛍️ 创建新买家 ===")
    
    # 【新增功能】：老板自定义 UID
    custom_uid = input("请输入自定义客户 ID (例如 vip_zhang，直接回车则随机生成): ").strip()
    if custom_uid:
        uid = custom_uid
    else:
        uid = f"usr_{uuid.uuid4().hex[:8]}"

    try:
        initial_balance = int(input("请输入初始 Token 数量 (默认 100): ") or 100)
        cost_per_room = int(input("请输入单次建房消耗 (默认 10): ") or 10)
    except ValueError:
        print("❌ 输入无效，请输入数字。")
        return

    # 生成专属访问路径
    access_path = generate_access_path()

    data = {
        "uid": uid,
        "access_path": access_path,
        "token_balance": initial_balance,
        "token_cost": cost_per_room
    }

    try:
        response = supabase.table('buyers').insert(data).execute()
        print("\n✅ [发卡成功] 新客户已入库！")
        print("-" * 40)
        print(f"客户 UID (用于后台管理): {uid}")
        print(f"初始 Token: {initial_balance}")
        print(f"单次消耗: {cost_per_room}")
        print(f"⚠️ 客户专属管理链接 (请将此链接发给买家):")
        print(f"👉 /manage/{access_path}")
        print("-" * 40)
    except Exception as e:
        # 捕捉因为 UID 重复导致的数据库报错
        if 'duplicate key value violates unique constraint' in str(e).lower():
            print(f"\n❌ 创建失败: 客户 ID '{uid}' 已存在，请换一个名字！")
        else:
            print(f"\n❌ 创建失败: {e}")

def list_all_buyers():
    """功能 2：查看所有客户状态"""
    print("\n=== 📊 客户资产列表 ===")
    try:
        response = supabase.table('buyers').select('*').execute()
        buyers = response.data
        
        if not buyers:
            print("当前没有任何客户记录。")
            return

        print(f"{'UID':<15} | {'剩余 Token':<12} | {'单次消耗':<10} | {'专属哈希 (Access Path)'}")
        print("-" * 70)
        for b in buyers:
            print(f"{b['uid']:<15} | {b['token_balance']:<12} | {b['token_cost']:<10} | {b['access_path']}")
        print("-" * 70)
        print(f"共计 {len(buyers)} 位客户。")
    except Exception as e:
        print(f"\n❌ 查询失败: {e}")

def recharge_buyer():
    """功能 3：为老客户充值"""
    print("\n=== 💰 客户充值 ===")
    uid = input("请输入要充值的客户 UID: ").strip()
    if not uid:
        return

    try:
        # 先查询当前余额
        res = supabase.table('buyers').select('token_balance').eq('uid', uid).execute()
        if not res.data:
            print("❌ 未找到该客户，请检查 UID 是否正确。")
            return
            
        current_balance = res.data[0]['token_balance']
        print(f"当前剩余 Token: {current_balance}")
        
        recharge_amount = int(input("请输入要【增加】的 Token 数量 (例如 500): "))
        new_balance = current_balance + recharge_amount

        # 更新数据库
        supabase.table('buyers').update({'token_balance': new_balance}).eq('uid', uid).execute()
        print(f"\n✅ [充值成功] 客户 {uid} 的余额已更新为: {new_balance}")

    except ValueError:
        print("❌ 输入无效，请输入数字。")
    except Exception as e:
        print(f"\n❌ 充值失败: {e}")

def main_menu():
    while True:
        print("\n" + "="*40)
        print("🚀 E2EE 商业发卡与客户管理系统")
        print("="*40)
        print("1. ➕ 创建新买家 (发卡/生成专属链接)")
        print("2. 📊 查看所有客户状态")
        print("3. 💰 为指定客户充值 Token")
        print("4. 🚪 退出程序")
        print("="*40)
        
        choice = input("👉 请选择操作 (1-4): ").strip()
        
        if choice == '1':
            create_new_buyer()
        elif choice == '2':
            list_all_buyers()
        elif choice == '3':
            recharge_buyer()
        elif choice == '4':
            print("👋 拜拜！")
            break
        else:
            print("⚠️ 无效选择，请重试。")

if __name__ == "__main__":
    main_menu()
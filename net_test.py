import requests
import os
import sys
import json
import time

# ===================== 配置区域 =====================
# 请替换为你自己的自定义 URL 和 KEY
# 注意：自定义 URL 通常以 /v1 结尾，但也取决于你的服务提供商
API_KEY = "sk-RUQ1ZOgfeMvRMVadqW-RoA" 
BASE_URL = "https://llmapi.blsc.cn/v1" 

# 如果你的服务商不需要 /v1，请自行修改上面的 BASE_URL
# 模型名称，如果你的自定义接口不支持 gpt-3.5-turbo，请修改
MODEL_NAME = "DeepSeek-V3.2"
# ===================================================

def run_diagnostic():
    print(f"\n{'='*20} 开始诊断 {'='*20}")
    
    # 1. 检查 Python 环境和代理设置
    print("[1/3] 检查本地环境...")
    print(f"   Python 版本: {sys.version.split()[0]}")
    
    # 检查系统环境变量中的代理设置
    # 很多时候，电脑上开过 VPN 或抓包工具，会留下环境变量，导致 Python 请求失败
    proxies = {
        'http': os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY'),
        'https': os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY')
    }
    
    if proxies['http'] or proxies['https']:
        print(f"   ⚠️ 警告: 检测到系统代理环境变量!")
        print(f"   HTTP_PROXY: {proxies['http']}")
        print(f"   HTTPS_PROXY: {proxies['https']}")
        print("   (如果网络环境相同但连不上，通常是因为这台电脑残留了代理设置)")
    else:
        print("   ✅ 未检测到强制代理环境变量 (Requests 将使用系统默认设置)")

    # 2. 构造请求
    print("\n[2/3] 准备发送请求...")
    target_url = f"{BASE_URL.rstrip('/')}/chat/completions"
    print(f"   目标 URL: {target_url}")
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "user", "content": "你好，请回复我：测试成功，现在几点？"}
        ],
        "temperature": 0.7
    }

    # 3. 发送请求并捕获详细错误
    print(f"   正在发送内容: '你好，请回复我：测试成功' ...")
    start_time = time.time()
    
    try:
        # timeout 设置为 10 秒，避免无限等待
        response = requests.post(target_url, headers=headers, json=payload, timeout=10)
        elapsed = time.time() - start_time
        
        print(f"\n[3/3] 响应接收 (耗时 {elapsed:.2f}秒)")
        print(f"   HTTP 状态码: {response.status_code}")
        
        if response.status_code == 200:
            print(f"   ✅ 连接成功！")
            try:
                data = response.json()
                content = data['choices'][0]['message']['content']
                print(f"   🤖 AI 回复内容:\n   {'-'*20}\n   {content}\n   {'-'*20}")
            except Exception as e:
                print(f"   ⚠️ 原始响应解析失败: {e}")
                print(f"   原始文本: {response.text}")
        else:
            print(f"   ❌ 请求被服务器拒绝")
            print(f"   错误详情: {response.text}")
            
            # 常见 HTTP 错误分析
            if response.status_code == 401:
                print("   👉 分析: API KEY 无效或格式错误。")
            elif response.status_code == 404:
                print("   👉 分析: URL 路径错误。请检查 BASE_URL 是否包含了 '/v1'？或者是否多写了？")
            elif response.status_code == 429:
                print("   👉 分析: 额度已用完或请求太频繁。")

    # ===================== 核心故障排查区 =====================
    except requests.exceptions.ProxyError as e:
        print("\n❌ 错误类型: 代理错误 (ProxyError)")
        print(f"详情: {e}")
        print("👉 原因: 你的 Python 试图通过代理连接，但代理服务器拒绝或不通。")
        print("👉 解决: 检查代码运行环境是否有 `HTTP_PROXY` 环境变量，或关闭系统代理/VPN软件。")

    except requests.exceptions.SSLError as e:
        print("\n❌ 错误类型: SSL 证书错误 (SSLError)")
        print(f"详情: {e}")
        print("👉 原因: 电脑无法验证服务器的证书。")
        print("   1. 可能是公司防火墙/杀毒软件进行了 HTTPS 抓包（中间人）。")
        print("   2. 可能是 Python 环境缺少根证书。")
        print("👉 尝试: 如果是自建服务，可以临时在 requests.post 中添加 `verify=False` 参数测试。")

    except requests.exceptions.ConnectionError as e:
        print("\n❌ 错误类型: 连接错误 (ConnectionError)")
        print(f"详情: {e}")
        print("👉 原因: DNS 解析失败，或服务器直接拒绝了连接。")
        print("👉 解决: 检查这台电脑的 DNS 设置，或防火墙是否拦截了 Python。")

    except requests.exceptions.Timeout as e:
        print("\n❌ 错误类型: 请求超时 (Timeout)")
        print("👉 原因: 网络通，但是数据包回不来，或者服务器处理太慢。")

    except Exception as e:
        print(f"\n❌ 未知错误: {e}")

if __name__ == "__main__":
    run_diagnostic()
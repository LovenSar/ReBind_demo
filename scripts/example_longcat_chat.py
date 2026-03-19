"""示例：调用 LongCat Chat 兼容的 OpenAI 风格接口（与 rebind_demo 主流程无关）。

使用前请设置环境变量 OPENAI_API_KEY。仅作连通性/格式探测，勿把真实密钥写入仓库。
"""

import os

import requests

url = "https://api.longcat.chat/openai/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
    "Content-Type": "application/json"
}

data = {
    "model": "LongCat-Flash-Chat",
    "messages": [
        {"role": "user", "content": "Hello, please introduce yourself."}
    ],
    "max_tokens": 1000,
    "temperature": 0.7
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
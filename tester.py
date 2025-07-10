import os
import re
import glob
import socket
import base64
import time
import json
from urllib.parse import urlparse, unquote

def extract_links_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        return re.findall(r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+)', content)

def decode_vmess(link):
    try:
        raw = base64.b64decode(link[8:] + '===').decode('utf-8')
        json_part = re.findall(r'{.*}', raw)[0]
        data = json.loads(json_part)
        return data.get('add'), int(data.get('port')), data.get('ps', '')
    except:
        return None, None, ''

def decode_vless_trojan_ss(link):
    try:
        parsed = urlparse(link)
        host = parsed.hostname
        port = parsed.port
        remark = ''
        if '#' in link:
            remark = unquote(link.split('#')[-1])
        return host, port, remark
    except:
        return None, None, ''

def measure_latency(host, port, timeout=3):
    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        end = time.time()
        latency_ms = int((end - start) * 1000)  # ms
        return latency_ms
    except:
        return None

def save_sorted_configs(configs_by_protocol):
    for protocol, items in configs_by_protocol.items():
        if not items:
            continue

        # مرتب‌سازی بر اساس latency
        items.sort(key=lambda x: x['latency'])

        # تقسیم‌بندی بر اساس latency
        fast_items = [f"{i['link']} # {i['remark']} - {i['latency']} ms" for i in items if i['latency'] < 200]
        normal_items = [f"{i['link']} # {i['remark']} - {i['latency']} ms" for i in items if 200 <= i['latency'] <= 800]

        if fast_items:
            with open(f"fast_{protocol}.txt", "w", encoding='utf-8') as f:
                f.write("\n".join(fast_items))

        if normal_items:
            with open(f"{protocol}.txt", "w", encoding='utf-8') as f:
                f.write("\n".join(normal_items))

def main():
    configs_by_protocol = {'vmess': [], 'vless': [], 'ss': [], 'trojan': []}

    for file in glob.glob("sub*.txt"):
        print(f"📂 اسکن فایل: {file}")
        links = extract_links_from_file(file)

        for link in links:
            if link.startswith("vmess://"):
                host, port, remark = decode_vmess(link)
                protocol = 'vmess'
            else:
                host, port, remark = decode_vless_trojan_ss(link)
                if link.startswith("vless://"):
                    protocol = 'vless'
                elif link.startswith("ss://"):
                    protocol = 'ss'
                elif link.startswith("trojan://"):
                    protocol = 'trojan'
                else:
                    continue

            if not host or not port:
                continue

            if not remark:
                remark = "NoRemark"

            latency = measure_latency(host, port)
            if latency is None or latency > 800:
                continue

            configs_by_protocol[protocol].append({
                'link': link,
                'remark': remark,
                'latency': latency
            })

    save_sorted_configs(configs_by_protocol)
    print("✅.")

if __name__ == "__main__":
    main()
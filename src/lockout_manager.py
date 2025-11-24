from datetime import datetime, timedelta

# Tracks locked IPs -> unlock time
locked_ips = {}

LOCKOUT_MINUTES = 15  # You can change this

def lock_ip(ip: str):
    unlock_time = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
    locked_ips[ip] = unlock_time
    print(f"[LOCKOUT] IP {ip} locked until {unlock_time}")

def is_ip_locked(ip: str) -> bool:
    if ip not in locked_ips:
        return False
    
    if datetime.now() >= locked_ips[ip]:
        # Lock expired
        del locked_ips[ip]
        return False

    return True

def get_lockout_info(ip: str):
    return locked_ips.get(ip)
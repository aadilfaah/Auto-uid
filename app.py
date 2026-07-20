import os, sys, time, json, ssl, socket, threading, asyncio, base64, binascii, re, jwt, pickle
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from flask import Flask, request, jsonify, render_template_string

import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.timestamp_pb2 import Timestamp

# custom project modules
from byte import *
from byte import xSEndMsg, Auth_Chat
from xHeaders import *
from black9 import openroom, spmroom
import xKEys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== ফ্লাস্ক অ্যাপ ====================
app = Flask(__name__)

# ==================== গ্লোবাল ভেরিয়েবল ====================
connected_clients = {}
connected_clients_lock = threading.Lock()
active_power_targets = {}
active_power_lock = threading.Lock()
spam_threads = {}
spam_threads_lock = threading.Lock()
auto_uids = []  # List of UIDs from auto_uid.txt
smart_target_statuses = {}  # প্রতিটি টার্গেটের বর্তমান স্ট্যাটাস সেভ রাখার জন্য
auto_spam_active = False
auto_spam_thread = None
refresh_timer = None

# Smart spam tracking
smart_monitor_threads = {}
smart_monitor_lock = threading.Lock()
target_group_leaders = {}  # target -> leader
leader_spam_active = {}  # leader -> bool

# নতুন দুটি লিস্ট
NORMAL_ACCOUNTS = []
INVITE_ACCOUNTS = []

C = "\033[96m"
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
RS = "\033[0m"
BOLD = "\033[1m"

# ==================== STATUS CHECKER MODULE (Built-in) ====================
_ID = '4575104506'
_PW = 'TORIKUL_TORIKUL_E6H3H'
_TTL = 6 * 60 * 60

_Hr = {
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.11f1',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB54',
}

_cx = {}

def _rdVr(data, pos):
    n = 0
    sh = 0
    while True:
        b = data[pos]
        pos += 1
        n |= (b & 0x7F) << sh
        sh += 7
        if not b & 0x80:
            break
    return n, pos

def _pbF(data):
    out = {}
    pos = 0
    while pos < len(data):
        try:
            tag, pos = _rdVr(data, pos)
            fn = tag >> 3
            wt = tag & 0x7
            if wt == 0:
                v, pos = _rdVr(data, pos)
                out[fn] = v
            elif wt == 2:
                ln, pos = _rdVr(data, pos)
                out[fn] = data[pos:pos+ln]
                pos += ln
            elif wt == 1:
                out[fn] = data[pos:pos+8]
                pos += 8
            elif wt == 5:
                out[fn] = data[pos:pos+4]
                pos += 4
            else:
                break
        except:
            break
    return out

async def _vr(n):
    h = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        h.append(b)
        if not n:
            break
    return bytes(h)

async def _enc(hx, k, v):
    return AES.new(k, AES.MODE_CBC, v).encrypt(pad(bytes.fromhex(hx), 16)).hex()

async def _hx(n):
    f = hex(n)[2:]
    return ('0' + f) if len(f) == 1 else f

async def _var(fn, val):
    return await _vr((fn << 3) | 0) + await _vr(val)

async def _len(fn, val):
    e = val.encode() if isinstance(val, str) else val
    return await _vr((fn << 3) | 2) + await _vr(len(e)) + e

async def _pb(flds):
    p = bytearray()
    for f, v in flds.items():
        if isinstance(v, dict):
            p.extend(await _len(f, await _pb(v)))
        elif isinstance(v, int):
            p.extend(await _var(f, v))
        elif isinstance(v, (str, bytes)):
            p.extend(await _len(f, v))
    return p

async def _pk(px, n, k, v):
    e = await _enc(px, k, v)
    _ = await _hx(len(e) // 2)
    m = {2: '000000', 3: '00000', 4: '0000', 5: '000'}
    return bytes.fromhex(n + m.get(len(_), '000000') + _ + e)

async def _fix(rs):
    d = {}
    for r in rs:
        fd = {'wire_type': r.wire_type}
        if r.wire_type in ('varint', 'string', 'bytes'):
            fd['data'] = r.data
        elif r.wire_type == 'length_delimited':
            fd['data'] = await _fix(r.data.results)
        d[r.field] = fd
    return d

async def OpEnSq(K, V, region="BD"):
    fields = {1: 1, 2: {2: "\u0001", 3: 1, 4: 1, 5: "en", 9: 1, 11: 1, 13: 1, 14: {2: 5756, 6: 11, 8: "1.122.1", 9: 2, 10: 4}}}
    packet_type = '0514' if region.lower() == "ind" else "0515"
    return await _pk((await _pb(fields)).hex(), packet_type, K, V)

async def cHSq(Nu, Uid, K, V, region="BD"):
    fields = {1: 17, 2: {1: int(Uid), 2: 1, 3: int(Nu - 1), 4: 62, 5: "\u001a", 8: 5, 13: 329}}
    packet_type = '0514' if region.lower() == "ind" else "0515"
    return await _pk((await _pb(fields)).hex(), packet_type, K, V)

async def SEnd_InV(Nu, Uid, K, V, region="BD"):
    fields = {1: 2, 2: {1: int(Uid), 2: region, 4: int(Nu)}}
    packet_type = '0514' if region.lower() == "ind" else "0515"
    return await _pk((await _pb(fields)).hex(), packet_type, K, V)

async def ExiT(K, V):
    fields = {1: 7, 2: {1: 0}} # idT 0 বা None
    return await _pk((await _pb(fields)).hex(), '0515', K, V)

async def _parse(hx):
    try:
        from protobuf_decoder.protobuf_decoder import Parser
        return json.dumps(await _fix(Parser().parse(hx)))
    except:
        return None

async def _uidEnc(uid):
    return (await _pb({1: int(uid)})).hex()[2:]

async def _stPkt(uid, k, v):
    ue = await _uidEnc(int(uid))
    return await _pk(f"080112090A05{ue}1005", '0F15', k, v)

async def _rmPkt(ruid, k, v):
    return await _pk((await _pb({1: 1, 2: {1: ruid, 3: {}, 4: 1, 6: 'en'}})).hex(), '0E15', k, v)

def _tdiff(ts):
    d = int((datetime.now() - datetime.fromtimestamp(ts)).total_seconds())
    return f"{(abs(d) % 3600) // 60:02}:{abs(d) % 60:02}"

def _pStatus(pkt):
    data = json.loads(pkt)
    if '5' not in data or 'data' not in data['5']:
        return {'status': 'OFFLINE'}
    jd = data['5']['data']
    if '1' not in jd or 'data' not in jd['1']:
        return {'status': 'OFFLINE'}
    d = jd['1']['data']
    if '3' not in d or 'data' not in d['3']:
        return {'status': 'OFFLINE'}
    st = d['3']['data']
    gc = d.get('9', {}).get('data', 0)
    cm = d.get('10', {}).get('data', 0) + 1 if '10' in d else 0
    go = d.get('8', {}).get('data', 0)
    tg = d.get('4', {}).get('data', 0)
    m5 = d.get('5', {}).get('data')
    m6 = d.get('6', {}).get('data')
    mn = sc = 0
    if tg:
        a, b = _tdiff(tg).split(':')
        mn = int(a)
        sc = int(b)
    
    if st == 4:
        return {
            'status': 'IN_ROOM',
            'room_uid': d.get('15', {}).get('data'),
            'players': f"{d.get('17',{}).get('data',0)}/{d.get('18',{}).get('data',0)}",
            'room_owner': d.get('1', {}).get('data')
        }
    
    base = {
        1: 'SOLO',
        2: 'INSQUAD',
        3: 'INGAME',
        5: 'INGAME',
        7: 'MATCHMAKING',
        6: 'SOCIAL_ISLAND'
    }.get(st, 'OFFLINE')
    
    mode = None
    f14 = d.get('14', {}).get('data')
    if f14 == 1:
        mode = 'TRAINING'
    elif f14 == 2:
        mode = 'SOCIAL_ISLAND'
    
    mm = {
        (2, 1): 'BR_RANK', (5, 23): 'TRAINING', (6, 15): 'CS_RANK',
        (1, 43): 'LONE_WOLF', (1, 1): 'BERMUDA', (1, 15): 'CLASH_SQUAD',
        (1, 29): 'CONVOY_CRUNCH', (1, 61): 'FREE_FOR_ALL'
    }
    if (m5, m6) in mm:
        mode = mm[(m5, m6)]
    
    res = {'status': base, 'mode': mode}
    if base == 'INSQUAD':
        res['squad_owner'] = go
        res['squad_size'] = f"{gc}/{cm}" if gc else None
    if base in ('INGAME', 'INSQUAD') and tg:
        res['time_playing'] = f"{mn}m {sc}s"
    return res

def _pRoom(pkt):
    data = json.loads(pkt)
    rd = data['5']['data']['1']['data']
    mm = {
        1: 'BERMUDA', 201: 'BATTLE_CAGE', 15: 'CLASH_SQUAD', 43: 'LONE_WOLF',
        3: 'RUSH_HOUR', 27: 'BOMB_SQUAD_5V5', 24: 'DEATH_MATCH'
    }
    return {
        'room_id': int(rd['1']['data']),
        'room_name': rd['2']['data'],
        'owner_uid': int(rd['37']['data']['1']['data']),
        'mode': mm.get(rd.get('4', {}).get('data'), 'UNKNOWN'),
        'players': f"{rd.get('6',{}).get('data',0)}/{rd.get('7',{}).get('data',0)}",
        'spectators': rd.get('9', {}).get('data', 0),
        'emulator': bool(rd.get('17', {}).get('data', 1)),
    }

async def _rAll(reader, timeout=5):
    buf = b''
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    return buf

async def _scan(buf, k, v):
    h = buf.hex()
    for mk, pt in [('0f00', '0f'), ('0e00', '0e')]:
        i = h.find(mk)
        if i != -1 and i % 2 == 0:
            return pt, h[i + 10:]
    if len(buf) > 5:
        pl = buf[5:]
        pl = pl[:len(pl) - (len(pl) % 16)]
        if len(pl) >= 16:
            try:
                dc = unpad(AES.new(k, AES.MODE_CBC, v).decrypt(pl), 16).hex()
                for mk, pt in [('0f00', '0f'), ('0e00', '0e')]:
                    i = dc.find(mk)
                    if i != -1 and i % 2 == 0:
                        return pt, dc[i + 10:]
            except:
                pass
    return None, None

async def _mkLogin(oid, atk):
    return await _pb({
        3: str(datetime.now())[:-7], 4: 'free fire', 5: 1, 7: '1.123.1',
        8: 'Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)',
        9: 'Handheld', 10: 'Verizon', 11: 'WIFI', 12: 1920, 13: 1080,
        14: '280', 15: 'ARM64 FP ASIMD AES VMH | 2865 | 4', 16: 3003,
        17: 'Adreno (TM) 640', 18: 'OpenGL ES 3.1 v1.46',
        19: 'Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57',
        20: '223.191.51.89', 21: 'en', 22: oid, 23: '4', 24: 'Handheld',
        25: {6: 55, 8: 81},
        29: atk, 30: 1, 73: 3, 78: 3, 79: 2, 81: '64',
        93: 'android', 97: 1, 98: 1, 99: '4', 100: '4',
    })

async def _auth(uid, tok, ts, k, v):
    uh = hex(uid)[2:]
    hd = {9: '0000000', 8: '00000000', 10: '000000', 7: '000000000'}.get(len(uh), '0000000')
    e = await _enc(tok.encode().hex(), k, v)
    el = await _hx(len(e) // 2)
    return f"0115{hd}{uh}{await _hx(ts)}00000{el}{e}"

async def _login():
    sx = ssl.create_default_context()
    sx.check_hostname = False
    sx.verify_mode = ssl.CERT_NONE

    async with aiohttp.ClientSession() as s:
        async with s.post('https://100067.connect.garena.com/oauth/guest/token/grant',
                         headers=_Hr,
                         data={
                             'uid': _ID,
                             'password': _PW,
                             'response_type': 'token',
                             'client_type': '2',
                             'client_secret': '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3',
                             'client_id': '100067'
                         }, ssl=sx) as r:
            if r.status != 200:
                raise Exception(f"OAuth {r.status}")
            d = await r.json()
            oid = d['open_id']
            atk = d['access_token']

    raw = await _mkLogin(oid, atk)
    ep = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%').encrypt(pad(raw, 16))

    async with aiohttp.ClientSession() as s:
        async with s.post('https://loginbp.ggpolarbear.com/MajorLogin', data=ep, headers=_Hr, ssl=sx) as r:
            if r.status != 200:
                raise Exception(f"MajorLogin {r.status}")
            mr = await r.read()

    mlr = _pbF(mr)
    tok = mlr[8].decode()
    tgt = mlr[1]
    k = mlr[22]
    v = mlr[23]
    ts = mlr[21]
    url = mlr[10].decode()

    h2 = {**_Hr, 'Authorization': f'Bearer {tok}'}
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{url}/GetLoginData", data=ep, headers=h2, ssl=sx) as r:
            if r.status != 200:
                raise Exception(f"GetLoginData {r.status}")
            lr = await r.read()

    ld = _pbF(lr)
    ip, port = ld[14].decode().split(':')
    at = await _auth(int(tgt), tok, int(ts), k, v)
    return {
        'account_id': tgt,
        'token': tok,
        'key': k,
        'iv': v,
        'ip': ip,
        'port': int(port),
        'auth': at,
        'exp': time.time() + _TTL
    }

def _sess():
    global _cx
    if 's' in _cx and _cx['s'] and time.time() < _cx['s']['exp']:
        return _cx['s']
    _cx['s'] = asyncio.run(_login())
    return _cx['s']

async def _query(uid, sx):
    rd, wr = await asyncio.open_connection(sx['ip'], sx['port'])
    try:
        wr.write(bytes.fromhex(sx['auth']))
        await wr.drain()
        await _rAll(rd, timeout=3)
        pkt = await _stPkt(uid, sx['key'], sx['iv'])
        wr.write(pkt)
        await wr.drain()
        buf = await _rAll(rd, timeout=5)
        if not buf:
            return {'status': 'NO_RESPONSE'}
        pt, pl = await _scan(buf, sx['key'], sx['iv'])
        if pt == '0f':
            raw = await _parse(pl)
            if not raw:
                return {'status': 'PARSE_ERROR'}
            info = _pStatus(raw)
            if info.get('status') == 'IN_ROOM':
                wr.write(await _rmPkt(int(info['room_uid']), sx['key'], sx['iv']))
                await wr.drain()
                rb = await _rAll(rd, timeout=5)
                if rb:
                    rt, rp = await _scan(rb, sx['key'], sx['iv'])
                    if rt == '0e':
                        rr = await _parse(rp)
                        if rr:
                            info['room_info'] = _pRoom(rr)
            return info
        elif pt == '0e':
            raw = await _parse(pl)
            return _pRoom(raw) if raw else {'status': 'PARSE_ERROR'}
        return {'status': 'UNKNOWN', 'buf': buf.hex()[:120]}
    finally:
        wr.close()
        try:
            await wr.wait_closed()
        except:
            pass

def check_user_status(uid):
    try:
        session = _sess()
        result = asyncio.run(_query(int(uid), session))
        return result
    except Exception as e:
        print(f"DEBUG ERROR: {str(e)}") # এটি Render-এর logs-এ দেখাবে
        return {'status': 'ERROR', 'error': str(e)}

def is_user_online(uid):
    """Check if a user is online"""
    status = check_user_status(uid)
    return status.get('status', 'OFFLINE') not in ['OFFLINE', 'ERROR', 'NO_RESPONSE']

def get_detailed_status(uid):
    """Get detailed status information"""
    status = check_user_status(uid)
    
    detailed = {
        'uid': str(uid),
        'timestamp': datetime.now().isoformat(),
        'is_online': status.get('status', 'OFFLINE') not in ['OFFLINE', 'ERROR', 'NO_RESPONSE'],
        'status': status.get('status', 'UNKNOWN'),
        'mode': status.get('mode', 'N/A'),
    }
    
    if status.get('status') == 'INSQUAD':
        detailed['squad_owner'] = status.get('squad_owner')
        detailed['squad_size'] = status.get('squad_size')
    elif status.get('status') == 'IN_ROOM':
        detailed['room_owner'] = status.get('room_owner')
        detailed['players'] = status.get('players')
        if status.get('room_info'):
            detailed['room_details'] = status['room_info']
    
    if status.get('time_playing'):
        detailed['time_playing'] = status['time_playing']
    
    return detailed

# ==================== স্মার্ট স্প্যাম মনিটর ====================
def monitor_target_smart(target_uid):
    """
    Smart monitor that automatically starts/stops spam based on target status
    Also handles group leaders
    """
    print(f"{C}🔍 SMART MONITOR started for target: {target_uid}{RS}")
    
    last_status = None
    is_currently_spamming = False
    leader_spam_started = set()
    
    while True:
        with smart_monitor_lock:
            if target_uid not in smart_monitor_threads:
                print(f"{Y}📌 Smart monitor stopped for: {target_uid}{RS}")
                break
        
        try:
            # Get target status
            status_info = get_detailed_status(target_uid)
            current_status = status_info.get('status', 'OFFLINE')
            is_online = status_info.get('is_online', False)
            mode = status_info.get('mode', '')
            squad_owner = status_info.get('squad_owner')
            
            # Determine if spam should be active
            should_spam = False
            spam_reason = ""
            
            if not is_online or current_status == 'OFFLINE':
                spam_reason = "Target is OFFLINE"
                should_spam = False
            elif current_status == 'INGAME':
                spam_reason = f"Target is IN-GAME ({mode})"
                should_spam = False
            elif current_status == 'MATCHMAKING':
                spam_reason = "Target is MATCHMAKING"
                should_spam = False
            elif current_status == 'SOLO':
                spam_reason = "Target is SOLO - READY TO SPAM"
                should_spam = True
            elif current_status == 'SOCIAL_ISLAND':
                spam_reason = "Target is on SOCIAL ISLAND - READY TO SPAM"
                should_spam = True
            elif current_status == 'IN_ROOM':
                spam_reason = "Target is in ROOM - READY TO SPAM"
                should_spam = True
            elif current_status == 'INSQUAD':
                if squad_owner and str(squad_owner) != str(target_uid):
                    spam_reason = f"Target is in squad, leader: {squad_owner} - SPAMMING LEADER"
                    should_spam = True
                    
                    # Also spam the leader if not already
                    leader_uid = str(squad_owner)
                    if leader_uid not in leader_spam_started:
                        print(f"{G}🎯 Starting spam on group leader: {leader_uid}{RS}")
                        start_multi_spam([leader_uid])
                        leader_spam_started.add(leader_uid)
                        target_group_leaders[target_uid] = leader_uid
                else:
                    spam_reason = "Target is squad owner - READY TO SPAM"
                    should_spam = True
            else:
                spam_reason = f"Status: {current_status} - CHECKING"
                should_spam = is_online
            
            # Control spam based on status
            if should_spam and not is_currently_spamming:
                # Start spam on target
                print(f"{G}▶️ SMART: Starting spam on {target_uid} - {spam_reason}{RS}")
                start_multi_spam([target_uid])
                is_currently_spamming = True
                
            elif not should_spam and is_currently_spamming:
                # Stop spam on target
                print(f"{R}⏸️ SMART: Stopping spam on {target_uid} - {spam_reason}{RS}")
                stop_spam(target_uid)
                is_currently_spamming = False
            
            # Check if leader left squad (target is no longer in squad with that leader)
            if current_status != 'INSQUAD' and target_uid in target_group_leaders:
                old_leader = target_group_leaders[target_uid]
                print(f"{Y}👋 Target left squad, stopping leader spam: {old_leader}{RS}")
                stop_spam(old_leader)
                del target_group_leaders[target_uid]
                if old_leader in leader_spam_started:
                    leader_spam_started.discard(old_leader)
            
            # Status change notification
            if last_status != current_status:
                # আপনার দেওয়া মাল্টি-লাইন ফরম্যাটে কনসোল প্রিন্ট
                status_icon = "🟢 ONLINE" if is_online else "⚫ OFFLINE"
                print(f"\n{BOLD}UID:        {target_uid}")
                print(f"  Status:     {status_icon}")
                print(f"  Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RS}")
                
                # স্ট্যাটাস পরিবর্তনের সাধারণ লগ
                print(f"{C}Status changed for {target_uid}: {last_status} → {current_status}{RS}\n")
                
                last_status = current_status
                
                # প্যানেলে স্ট্যাটাস দেখানোর জন্য গ্লোবাল ভেরিয়েবলে আপডেট (এটি শুরুতে ডিক্লেয়ার করে নিবেন)
                with smart_monitor_lock:
                    if 'smart_target_statuses' not in globals():
                        global smart_target_statuses
                        smart_target_statuses = {}
                    smart_target_statuses[target_uid] = current_status
            
            # Also check leader status if we're spamming a leader
            if target_uid in target_group_leaders:
                leader_uid = target_group_leaders[target_uid]
                leader_status = get_detailed_status(leader_uid)
                if not leader_status.get('is_online', False):
                    print(f"{Y}⚠️ Leader {leader_uid} went offline, stopping{RS}")
                    stop_spam(leader_uid)
                    
        except Exception as e:
            print(f"{R}❌ Smart monitor error for {target_uid}: {e}{RS}")
        
        # Check every 10 seconds
        time.sleep(3)

def start_smart_monitor(target_uid):
    """Start smart monitoring for a target"""
    with smart_monitor_lock:
        if target_uid in smart_monitor_threads:
            return False, f"Already monitoring {target_uid}"
        
        thread = Thread(target=monitor_target_smart, args=(target_uid,), daemon=True)
        smart_monitor_threads[target_uid] = thread
        thread.start()
        return True, f"Smart monitoring started for {target_uid}"

def stop_smart_monitor(target_uid):
    """Stop smart monitoring for a target"""
    with smart_monitor_lock:
        if target_uid in smart_monitor_threads:
            del smart_monitor_threads[target_uid]
            # Also stop any spam on this target
            stop_spam(target_uid)
            return True, f"Smart monitoring stopped for {target_uid}"
    return False, f"No monitor found for {target_uid}"

# ==================== AUTO_UID.TXT LOADER ====================
def load_auto_uids(filename="auto_uid.txt"):
    """Load UIDs from auto_uid.txt (one per line)"""
    global auto_uids
    uids = []
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                uid = line.strip()
                if uid and not uid.startswith("#") and uid.isdigit():
                    uids.append(uid)
        auto_uids = uids
        print(f"{G}📦 Loaded {len(auto_uids)} UIDs from auto_uid.txt{RS}")
    except FileNotFoundError:
        print(f"{Y}⚠️ auto_uid.txt not found! Creating...{RS}")
        with open(filename, "w") as f:
            f.write("# Add UIDs here (one per line)\n")
            f.write("# Example:\n")
            f.write("# 1234567890\n")
            f.write("# 0987654321\n")
        auto_uids = []
    return auto_uids

def save_auto_uids(uids):
    """Save UIDs to auto_uid.txt"""
    try:
        with open("auto_uid.txt", "w", encoding="utf-8") as file:
            file.write("# Add UIDs here (one per line)\n")
            file.write("# Example:\n")
            for uid in uids:
                file.write(f"{uid}\n")
    except Exception as e:
        print(f"{R}❌ Failed to save auto_uid.txt: {e}{RS}")

# ==================== স্প্যাম ফাংশন (মাল্টি-টার্গেট) ====================
def spam_worker_multi(targets_list):
    """
    সংশোধিত মাল্টি-টার্গেট স্প্যামার:
    - inv.txt থেকে আসা আইডিগুলো Squad 5 Invite দিবে।
    - accs.txt থেকে আসা আইডিগুলো Room Spam দিবে।
    """
    global auto_spam_active
    auto_spam_active = True 
    
    print(f"\n{G}🎯 MULTI-ACTION STARTED (inv.txt = Invite | accs.txt = Room Spam){RS}")
    print(f"{C}🚀 Targeting: {', '.join(targets_list)}{RS}")

    def run_sync_packet(coro):
        try:
            return asyncio.run(coro)
        except:
            return None

    while auto_spam_active:
        with active_power_lock:
            current_targets = list(active_power_targets.keys())
            if not current_targets:
                break

        with connected_clients_lock:
            clients_list = list(connected_clients.values())

        if not clients_list:
            time.sleep(2)
            continue

        for target_id in current_targets:
            if not auto_spam_active:
                break

            for client in clients_list:
                with active_power_lock:
                    if target_id not in active_power_targets:
                        break

                try:
                    if hasattr(client, 'CliEnts2') and client.key:
                        
                        # --- [১] যদি আইডিটি inv.txt এর হয় (is_inviter=True) ---
                        if getattr(client, 'is_inviter', False):
                            async def invite_sequence():
                                try:
                                    # ইনভাইট প্যাকেটের ধাপগুলো
                                    p1 = await OpEnSq(client.key, client.iv)
                                    client.CliEnts2.send(p1)
                                    await asyncio.sleep(0.06)
                                    
                                    p2 = await cHSq(5, target_id, client.key, client.iv)
                                    client.CliEnts2.send(p2)
                                    await asyncio.sleep(0.06)
                                    
                                    p3 = await SEnd_InV(5, target_id, client.key, client.iv)
                                    client.CliEnts2.send(p3)
                                    await asyncio.sleep(0.06)
                                    
                                    p4 = await ExiT(client.key, client.iv)
                                    client.CliEnts2.send(p4)
                                except:
                                    pass
                            
                            run_sync_packet(invite_sequence())

                        # --- [২] যদি আইডিটি accs.txt এর হয় (is_inviter=False) ---
                        else:
                            try:
                                # রুম স্প্যামিং প্যাকেটের ধাপগুলো
                                open_pkt = openroom(client.key, client.iv)
                                client.CliEnts2.send(open_pkt)
                                
                                spam_pkt = spmroom(client.key, client.iv, target_id)
                                client.CliEnts2.send(spam_pkt)
                            except:
                                pass
                except:
                    pass
                
                time.sleep(0.01)
        time.sleep(0.1)

    # Cleanup
    with spam_threads_lock:
        for tid in targets_list:
            if tid in spam_threads:
                del spam_threads[tid]

    print(f"\n{R}{'='*50}{RS}")
    print(f"{R}🛑 MULTI-SPAM STOPPED ON {len(targets_list)} TARGETS{RS}")
    print(f"{R}{'='*50}{RS}\n")

def start_multi_spam(targets_list):
    """
    মাল্টিপল টার্গেটে স্প্যাম শুরু করার ফাংশন।
    এটি চেক করে টার্গেট অলরেডি লিস্টে আছে কি না, তারপর নতুন থ্রেড চালু করে।
    """
    global auto_spam_active
    new_targets = []
    
    # স্প্যামার গ্লোবাল ফ্ল্যাগ অন করা (এটি না করলে স্প্যামার লুপ ঘুরবে না)
    auto_spam_active = True
    
    with active_power_lock:
        for target in targets_list:
            target = str(target).strip() # UID স্ট্রিং এবং ক্লিন হিসেবে রাখা ভালো
            if target and target not in active_power_targets:
                # টার্গেট ইনফো সেভ করা
                active_power_targets[target] = {
                    'active': True,
                    'start_time': datetime.now(),
                    'duration': None  # Unlimited মোড
                }
                new_targets.append(target)
    
    if new_targets:
        # নতুন টার্গেটগুলোর জন্য স্প্যামার থ্রেড তৈরি করা
        # এখানে daemon=True রাখা হয়েছে যাতে মেইন অ্যাপ বন্ধ হলে থ্রেডও বন্ধ হয়
        thread = Thread(target=spam_worker_multi, args=(new_targets,), daemon=True)
        
        with spam_threads_lock:
            for tid in new_targets:
                # প্রতিটি টার্গেটের বিপরীতে থ্রেড রেফারেন্স রাখা
                spam_threads[tid] = thread
        
        # থ্রেড স্টার্ট করা
        thread.start()
        
        print(f"{G}✅ Success: Started spam on {len(new_targets)} targets.{RS}")
        return True, f"Started spam on {len(new_targets)} targets"
    
    # যদি কোনো নতুন টার্গেট না থাকে (সবগুলো যদি অলরেডি লিস্টে থাকে)
    print(f"{Y}⚠️ Warning: All provided targets are already being spammed.{RS}")
    return False, "Targets are already active or list was empty"

def stop_spam(target_id):
    """Stop spam on a specific target"""
    with active_power_lock:
        if target_id in active_power_targets:
            del active_power_targets[target_id]
            return True, f"Spam stopped on: {target_id}"
        return False, f"No active spam on: {target_id}"

def stop_all_spam():
    """Stop all spam"""
    global auto_spam_active
    auto_spam_active = False
    with active_power_lock:
        targets = list(active_power_targets.keys())
        for target in targets:
            del active_power_targets[target]
    return True, f"Stopped all spam ({len(targets)} targets)"

def get_status():
    """
    ওয়েব প্যানেলের জন্য বর্তমান স্প্যামিং এবং মনিটরিং স্ট্যাটাস তৈরি করার ফাংশন।
    এটি সক্রিয় টার্গেট, কানেক্টেড একাউন্ট এবং স্মার্ট মনিটরের স্ট্যাটাস রিটার্ন করে।
    """
    targets_info = []
    
    # ১. অ্যাক্টিভ টার্গেট লিস্ট (যাদের উপর বর্তমানে স্প্যাম চলছে)
    with active_power_lock:
        active_targets = list(active_power_targets.keys())
        for target in active_targets:
            info = active_power_targets.get(target, {})
            start_time = info.get('start_time')
            
            # স্প্যাম কতক্ষণ ধরে চলছে তা ক্যালকুলেট করা
            if start_time:
                elapsed = (datetime.now() - start_time).total_seconds()
                elapsed_minutes = int(elapsed / 60)
            else:
                elapsed_minutes = 0
                
            targets_info.append({
                'uid': target,
                'duration': None,
                'elapsed_minutes': elapsed_minutes,
                'is_unlimited': True
            })
    
    # ২. কানেক্টেড একাউন্টস (বট আইডি যেগুলো বর্তমানে অনলাইন আছে)
    with connected_clients_lock:
        accounts_count = len(connected_clients)
        # প্যানেলে ভিড় এড়াতে প্রথম ৫০টি আইডির লিস্ট পাঠানো
        accounts_list = list(connected_clients.keys())
    
    # ৩. স্মার্ট মনিটর স্ট্যাটাস (গেম স্ট্যাটাস সহ)
    monitored_targets = []
    with smart_monitor_lock:
        # বর্তমানে যে আইডিগুলো স্মার্ট মনিটরিং লিস্টে আছে
        current_monitors = list(smart_monitor_threads.keys())
        
        for uid in current_monitors:
            # গ্লোবাল smart_target_statuses থেকে ওই আইডির বর্তমান স্ট্যাটাস নেওয়া
            # যদি স্ট্যাটাস না থাকে তবে 'CHECKING...' দেখাবে
            current_st = smart_target_statuses.get(uid, "SCANNING...")
            
            monitored_targets.append({
                'uid': uid,
                'status': current_st
            })
    
    # ৪. সম্পূর্ণ ডাটা অবজেক্ট তৈরি
    return {
        'active_targets': targets_info,           # স্প্যামিং লিস্ট
        'active_count': len(targets_info),       # মোট স্প্যামিং টার্গেট সংখ্যা
        'accounts_count': accounts_count,         # অনলাইন বট একাউন্ট সংখ্যা
        'accounts_list': accounts_list[:50],     # অনলাইন বটদের ইউআইডি
        'auto_uids': auto_uids,                  # auto_uid.txt থেকে লোড করা আইডি
        'auto_active': auto_spam_active,         # অটো স্প্যাম চালু আছে কি না
        'smart_monitored': monitored_targets      # স্ট্যাটাসসহ স্মার্ট মনিটরিং লিস্ট
    }

# ==================== AUTO REFRESH FUNCTION (7 MINUTES) ====================
def auto_refresh_and_restart():
    """Refresh everything every 7 minutes: clear spam, reload UIDs, restart"""
    global auto_spam_active, refresh_timer, auto_uids
    
    print(f"\n{Y}{'='*50}{RS}")
    print(f"{Y}🔄 AUTO REFRESH INITIATED (7 MINUTES CYCLE){RS}")
    print(f"{Y}{'='*50}{RS}\n")
    
    # Stop all current spam
    stop_all_spam()
    
    # Reload UIDs from auto_uid.txt
    load_auto_uids()
    
    # If there are UIDs in auto_uid.txt, restart auto spam with smart monitoring
    if auto_uids:
        print(f"{G}🔄 Restarting smart spam on {len(auto_uids)} auto UIDs...{RS}")
        for uid in auto_uids:
            start_smart_monitor(uid)
        auto_spam_active = True
    
    # Set next refresh
    if refresh_timer:
        refresh_timer.cancel()
    refresh_timer = threading.Timer(7 * 60, auto_refresh_and_restart)  # 7 minutes
    refresh_timer.daemon = True
    refresh_timer.start()
    
    print(f"{G}✅ Next auto-refresh in 7 minutes{RS}\n")

def start_auto_refresh():
    """Start the auto-refresh timer"""
    global refresh_timer
    if refresh_timer:
        refresh_timer.cancel()
    refresh_timer = threading.Timer(7 * 60, auto_refresh_and_restart)
    refresh_timer.daemon = True
    refresh_timer.start()
    print(f"{G}⏰ Auto-refresh timer started (every 7 minutes){RS}")

# ==================== ফ্লাস্ক রাউট ====================
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/start', methods=['POST'])  # ৫8৩ নম্বর লাইন
def api_start():                           # ৫8৪ নম্বর লাইন
    data = request.get_json()
    target_id = data.get('uid', '').strip()
    smart_mode = data.get('smart', False)
    
    if not target_id:
        return jsonify({'success': False, 'message': 'UID is required'})
    
    if smart_mode:
        success, message = start_smart_monitor(target_id)
        return jsonify({'success': success, 'message': message})
    else:
        success, message = start_multi_spam([target_id]) # এই লাইনটি spam_worker_multi কল করে
        return jsonify({'success': success, 'message': message})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    data = request.get_json()
    target_id = data.get('uid', '').strip()
    smart_mode = data.get('smart', False)
    
    if not target_id:
        return jsonify({'success': False, 'message': 'UID is required'})
    
    if smart_mode:
        success, message = stop_smart_monitor(target_id)
        return jsonify({'success': success, 'message': message})
    else:
        success, message = stop_spam(target_id)
        return jsonify({'success': success, 'message': message})

@app.route('/api/stop-all', methods=['POST'])
def api_stop_all():
    # Stop all smart monitors too
    with smart_monitor_lock:
        monitors = list(smart_monitor_threads.keys())
        for uid in monitors:
            del smart_monitor_threads[uid]
    
    success, message = stop_all_spam()
    return jsonify({'success': success, 'message': message})

@app.route('/api/status', methods=['GET'])
def api_status():
    status = get_status()
    return jsonify({'success': True, 'data': status})

@app.route('/api/accounts', methods=['GET'])
def api_accounts():
    with connected_clients_lock:
        return jsonify({
            'success': True,
            'count': len(connected_clients),
            'accounts': list(connected_clients.keys())
        })

@app.route('/api/auto-uids', methods=['GET'])
def api_get_auto_uids():
    return jsonify({'success': True, 'uids': auto_uids})

@app.route('/api/auto-uids', methods=['POST'])
def api_update_auto_uids():
    data = request.get_json()
    uids = data.get('uids', [])
    global auto_uids
    auto_uids = [uid.strip() for uid in uids if uid.strip().isdigit()]
    save_auto_uids(auto_uids)
    return jsonify({'success': True, 'message': f'Saved {len(auto_uids)} UIDs'})

@app.route('/api/start-auto', methods=['POST'])
def api_start_auto():
    global auto_spam_active
    if auto_uids:
        for uid in auto_uids:
            start_smart_monitor(uid)
        auto_spam_active = True
        return jsonify({'success': True, 'message': f'Smart auto spam started on {len(auto_uids)} UIDs'})
    return jsonify({'success': False, 'message': 'No UIDs in auto_uid.txt'})

@app.route('/api/stop-auto', methods=['POST'])
def api_stop_auto():
    global auto_spam_active
    auto_spam_active = False
    # Stop all smart monitors
    with smart_monitor_lock:
        monitors = list(smart_monitor_threads.keys())
        for uid in monitors:
            del smart_monitor_threads[uid]
    stop_all_spam()
    return jsonify({'success': True, 'message': 'Auto spam stopped'})

@app.route('/api/check-status', methods=['POST'])
def api_check_status():
    data = request.get_json()
    target_id = data.get('uid', '').strip()
    
    if not target_id:
        return jsonify({'success': False, 'message': 'UID is required'})
    
    status = get_detailed_status(target_id)
    return jsonify({'success': True, 'data': status})

# ==================== নতুন GET URL রাউট ====================
@app.route('/mahir', methods=['GET'])
def mahir_get_endpoint():
    # URL থেকে uid এবং mode প্যারামিটার নেওয়া
    target_id = request.args.get('uid', '').strip()
    # আপনি চাইলে মোডও সেট করতে পারেন, না দিলে ডিফল্টভাবে 'smart' চলবে
    mode = request.args.get('mode', 'smart').lower() 
    
    if not target_id:
        return jsonify({
            'success': False, 
            'message': 'UID প্রদান করুন। উদাহরণ: /mahir?uid=12345678'
        }), 400
    
    if not target_id.isdigit():
        return jsonify({
            'success': False, 
            'message': 'ভুল UID! শুধুমাত্র সংখ্যা ব্যবহার করুন।'
        }), 400

    if mode == 'smart':
        # স্মার্ট মনিটর চালু করা (অটোমেটিক স্ট্যাটাস চেক করে স্প্যাম করবে)
        success, message = start_smart_monitor(target_id)
    else:
        # নরমাল আনলিমিটেড স্প্যাম চালু করা
        success, message = start_multi_spam([target_id])

    if success:
        return jsonify({
            'success': True,
            'target_uid': target_id,
            'mode': mode,
            'message': message,
            'system_status': 'Running'
        })
    else:
        return jsonify({
            'success': False,
            'message': message
        })

@app.route('/api/smart-monitors', methods=['GET'])
def api_smart_monitors():
    with smart_monitor_lock:
        return jsonify({
            'success': True,
            'monitored': list(smart_monitor_threads.keys())
        })

# ==================== HTML টেমপ্লেট ====================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <title>NIROB SPAM - SMART Auto Target Tool</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-color: rgba(9, 14, 23, 0.85);
            --card-bg: rgba(17, 24, 38, 0.95);
            --text-main: #ffffff;
            --text-muted: #8b9bb4;
            --primary-blue: #00d4ff;
            --secondary-blue: #0051ff;
            --border-color: #233045;
            --glow-blue: rgba(0, 212, 255, 0.4);
            --danger: #ff3366;
            --success: #00cc66;
            --warning: #ffd700;
            --smart: #9b59b6;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Poppins', sans-serif; }
        body { background-color: #000; color: var(--text-main); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; overflow-x: hidden; }
        #matrix-canvas { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1; }
        
        .app-container { width: 100%; max-width: 550px; padding: 30px 20px; display: flex; flex-direction: column; gap: 25px; background: var(--bg-color); backdrop-filter: blur(8px); border-radius: 20px; border: 1px solid rgba(0, 212, 255, 0.1); box-shadow: 0 0 40px rgba(0, 0, 0, 0.8); z-index: 1; }
        
        .header { text-align: center; margin-bottom: 15px; }
        .premium-badge { color: #ffd700; font-size: 0.85rem; font-weight: 600; letter-spacing: 2px; display: flex; justify-content: center; gap: 10px; margin-bottom: 10px; }
        .main-title { font-size: 2.8rem; font-weight: 800; background: linear-gradient(90deg, var(--primary-blue), var(--secondary-blue)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 15px 0; }
        
        .card { background-color: var(--card-bg); border-radius: 20px; padding: 25px 20px; border: 1px solid var(--border-color); box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        .card-header { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
        .icon-circle { width: 40px; height: 40px; border-radius: 50%; background: rgba(26,35,51,0.9); display: flex; justify-content: center; align-items: center; color: var(--primary-blue); font-size: 1.2rem; }
        .card-title h3 { font-size: 1.2rem; font-weight: 600; }
        .card-title p { font-size: 0.75rem; color: var(--text-muted); }
        
        .input-group { margin-bottom: 15px; }
        .input-label { display: flex; align-items: center; gap: 8px; color: var(--text-muted); font-size: 0.85rem; margin-bottom: 8px; }
        input[type="text"].plain-input, textarea { width: 100%; background: rgba(9,14,23,0.7); border: 1px solid var(--border-color); color: white; padding: 15px; border-radius: 12px; font-size: 1rem; outline: none; }
        input[type="text"].plain-input:focus, textarea:focus { border-color: var(--primary-blue); box-shadow: 0 0 10px rgba(0,212,255,0.3); }
        textarea { resize: vertical; font-family: monospace; }
        
        .btn { width: 100%; padding: 14px; border: none; border-radius: 12px; font-size: 1rem; font-weight: 600; cursor: pointer; display: flex; justify-content: center; align-items: center; gap: 10px; transition: 0.3s; margin-top: 12px; }
        .btn-primary { background: linear-gradient(90deg, var(--secondary-blue), var(--primary-blue)); color: white; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0,212,255,0.3); }
        .btn-danger-outline { background: transparent; border: 1px solid var(--danger); color: var(--danger); }
        .btn-danger-outline:hover { background: rgba(255,51,102,0.1); transform: translateY(-2px); }
        .btn-warning { background: transparent; border: 1px solid #ffd700; color: #ffd700; }
        .btn-warning:hover { background: rgba(255,215,0,0.1); transform: translateY(-2px); }
        .btn-success { background: transparent; border: 1px solid var(--success); color: var(--success); }
        .btn-success:hover { background: rgba(0,204,102,0.1); transform: translateY(-2px); }
        .btn-smart { background: linear-gradient(90deg, #8e44ad, #9b59b6); color: white; }
        .btn-smart:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(155,89,182,0.3); }
        
        .console-box { background: #000; border: 1px solid var(--border-color); border-radius: 12px; height: 180px; padding: 15px; font-family: 'Courier New', monospace; font-size: 0.75rem; color: var(--primary-blue); overflow-y: auto; text-align: left; }
        .console-line { margin-bottom: 6px; }
        .console-line .time { color: var(--text-muted); margin-right: 10px; }
        .console-line .success { color: var(--success); }
        .console-line .error { color: var(--danger); }
        .console-line .info { color: var(--primary-blue); }
        .console-line .smart { color: #9b59b6; }
        
        .badge { background: rgba(0,212,255,0.1); color: var(--primary-blue); border: 1px solid var(--primary-blue); padding: 12px; border-radius: 12px; text-align: center; font-size: 0.8rem; font-weight: 600; margin-top: 15px; }
        .status-badge { background: rgba(0,204,102,0.1); color: var(--success); border: 1px solid var(--success); padding: 12px; border-radius: 12px; text-align: center; display: flex; justify-content: center; align-items: center; gap: 8px; margin-top: 10px; font-size: 0.8rem; font-weight: 600; }
        .status-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; animation: pulse 1.5s infinite; }
        .smart-badge { background: rgba(155,89,182,0.1); color: #9b59b6; border: 1px solid #9b59b6; margin-top: 5px; }
        
        @keyframes pulse { 0%,100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.3); opacity: 0.5; } }
        
        .active-list, .accounts-list { max-height: 200px; overflow-y: auto; margin-top: 10px; }
        .active-item { background: rgba(30,30,40,0.8); padding: 12px; margin: 8px 0; border-radius: 10px; display: flex; justify-content: space-between; align-items: center; border-left: 3px solid #38ef7d; }
        .active-uid { font-family: monospace; font-weight: bold; color: #38ef7d; font-size: 14px; }
        .smart-item { border-left-color: #9b59b6; }
        .stop-small { background: #eb3349; color: white; border: none; padding: 6px 18px; border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: bold; transition: 0.2s; }
        .stop-small:hover { background: #c0392b; }
        .account-item { background: rgba(30,30,40,0.6); padding: 6px 12px; margin: 4px 0; border-radius: 8px; font-family: monospace; font-size: 11px; color: #4facfe; }
        
        .flex-buttons { display: flex; gap: 12px; margin-top: 12px; }
        .flex-buttons .btn { margin-top: 0; }
        
        .refresh-badge { background: rgba(255,215,0,0.15); color: #ffd700; border: 1px solid #ffd700; border-radius: 12px; padding: 8px; text-align: center; font-size: 0.7rem; margin-top: 10px; }
        
        .copyright { text-align: center; color: var(--text-muted); font-size: 0.7rem; margin-top: 20px; }
        
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: #1a1a2e; border-radius: 10px; }
        ::-webkit-scrollbar-thumb { background: #ff6b6b; border-radius: 10px; }
        
        .mode-toggle { display: flex; gap: 10px; margin-bottom: 15px; }
        .mode-btn { flex: 1; padding: 10px; background: rgba(30,30,40,0.6); border: 1px solid var(--border-color); border-radius: 10px; cursor: pointer; text-align: center; transition: 0.3s; }
        .mode-btn.active { background: linear-gradient(90deg, var(--secondary-blue), var(--primary-blue)); border-color: var(--primary-blue); }
        .mode-btn.smart-mode.active { background: linear-gradient(90deg, #8e44ad, #9b59b6); }
    </style>
</head>
<body>
    <canvas id="matrix-canvas"></canvas>

    <div class="app-container">
        <div class="header">
            <div class="premium-badge"><i class="fa-solid fa-crown"></i> SMART EDITION</div>
            <h1 class="main-title">NIROB<br>SPAM</h1>
            <div class="premium-badge"><i class="fa-solid fa-brain"></i> AUTO STATUS MONITORING</div>
        </div>

        <!-- Auto UIDs Card -->
        <div class="card">
            <div class="card-header">
                <div class="icon-circle"><i class="fa-solid fa-file-alt"></i></div>
                <div class="card-title"><h3>AUTO UIDs (auto_uid.txt)</h3><p>Smart monitoring - Auto start/stop based on status</p></div>
            </div>
            <textarea id="autoUidsText" rows="4" placeholder="Enter UIDs (one per line)&#10;Example:&#10;1234567890&#10;0987654321"></textarea>
            <div class="flex-buttons">
                <button class="btn btn-success" onclick="saveAutoUids()"><i class="fa-solid fa-save"></i> SAVE</button>
                <button class="btn btn-smart" onclick="startAutoSpam()"><i class="fa-solid fa-brain"></i> START SMART</button>
                <button class="btn btn-danger-outline" onclick="stopAutoSpam()"><i class="fa-solid fa-stop"></i> STOP ALL</button>
            </div>
        </div>

        <!-- Single Target Card with Mode Toggle -->
        <div class="card">
            <div class="card-header">
                <div class="icon-circle"><i class="fa-solid fa-bullseye"></i></div>
                <div class="card-title"><h3>SINGLE TARGET</h3><p>Choose mode below</p></div>
            </div>
            <div class="mode-toggle">
                <div id="normalModeBtn" class="mode-btn active" onclick="setMode('normal')"><i class="fa-solid fa-fire"></i> NORMAL</div>
                <div id="smartModeBtn" class="mode-btn smart-mode" onclick="setMode('smart')"><i class="fa-solid fa-brain"></i> SMART</div>
            </div>
            <div class="input-group">
                <div class="input-label"><i class="fa-solid fa-crosshairs"></i> TARGET USER ID</div>
                <input type="text" id="startUid" class="plain-input" placeholder="Enter Game UID" inputmode="numeric">
            </div>
            <button class="btn btn-primary" onclick="startSpam()"><i class="fa-solid fa-play"></i> START</button>
            <button class="btn btn-smart" onclick="checkAndStartSmart()"><i class="fa-solid fa-search"></i> CHECK & START SMART</button>
        </div>

        <!-- Stop Card -->
        <div class="card">
            <div class="card-header">
                <div class="icon-circle"><i class="fa-solid fa-stop"></i></div>
                <div class="card-title"><h3>STOP SPAM</h3><p>Stop by UID or all</p></div>
            </div>
            <div class="input-group">
                <div class="input-label"><i class="fa-solid fa-crosshairs"></i> UID TO STOP</div>
                <input type="text" id="stopUid" class="plain-input" placeholder="Enter UID to Stop" inputmode="numeric">
            </div>
            <div class="flex-buttons">
                <button class="btn btn-danger-outline" onclick="stopSpam()"><i class="fa-solid fa-power-off"></i> STOP</button>
                <button class="btn btn-warning" onclick="stopAllSpam()"><i class="fa-solid fa-stop-circle"></i> STOP ALL</button>
            </div>
        </div>

        <!-- Status Card -->
        <div class="card">
            <div class="card-header">
                <div class="icon-circle"><i class="fa-solid fa-terminal"></i></div>
                <div class="card-title"><h3>Console & Status</h3><p>Live Logs</p></div>
            </div>
            
            <div class="console-box" id="consoleBox">
                <div class="console-line"><span class="time">[System]</span> SMART NIROB SPAM Ready.</div>
                <div class="console-line"><span class="time">[System]</span> Auto-refresh every 7 minutes.</div>
                <div class="console-line"><span class="time">[System]</span> Smart monitoring: Auto start/stop based on target status</div>
            </div>
            
            <div class="badge"><i class="fa-solid fa-infinity"></i> UNLIMITED SPAM MODE</div>
            <div class="status-badge">
                <div class="status-dot"></div>
                <span>STATUS: <span id="statusText">IDLE</span></span>
            </div>
            <div class="badge smart-badge">
                <i class="fa-solid fa-brain"></i> SMART MONITORING: <span id="smartCount">0</span> targets
            </div>
            <div class="refresh-badge">
                <i class="fa-solid fa-clock"></i> Auto-refresh every 7 minutes (clears & restarts)
            </div>
        </div>

        <!-- Active Targets Card -->
        <div class="card">
            <div class="card-header">
                <div class="icon-circle"><i class="fa-solid fa-list"></i></div>
                <div class="card-title"><h3>ACTIVE TARGETS</h3><p>Running Spam List</p></div>
            </div>
            <div id="activeSpamList" class="active-list">
                <div class="console-line">📭 No active targets</div>
            </div>
        </div>

        <!-- Smart Monitored Card -->
        <div class="card">
            <div class="card-header">
                <div class="icon-circle"><i class="fa-solid fa-brain"></i></div>
                <div class="card-title"><h3>SMART MONITORED</h3><p>Auto status tracking</p></div>
            </div>
            <div id="smartMonitoredList" class="active-list">
                <div class="console-line">📭 No smart monitored targets</div>
            </div>
        </div>

        <!-- Connected Accounts Card -->
        <div class="card">
            <div class="card-header">
                <div class="icon-circle"><i class="fa-solid fa-users"></i></div>
                <div class="card-title"><h3>CONNECTED ACCOUNTS</h3><p>Online Accounts</p></div>
            </div>
            <div id="accountsList" class="accounts-list">
                <div class="console-line">Loading...</div>
            </div>
        </div>

        <div class="copyright">
            NIROB SPAM <i class="fa-solid fa-heart" style="color: #00d4ff;"></i> SMART EDITION V6.0
        </div>
    </div>

    <script>
        let currentMode = 'normal';
        
        const canvas = document.getElementById('matrix-canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&'.split('');
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = Array(Math.floor(columns)).fill(1);

        function drawMatrix() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#00d4ff';
            ctx.font = fontSize + 'px monospace';
            drops.forEach((y, i) => {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, y * fontSize);
                if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
                drops[i]++;
            });
        }
        setInterval(drawMatrix, 35);
        window.addEventListener('resize', () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; });

        function logToConsole(message, type = 'info') {
            const consoleBox = document.getElementById('consoleBox');
            const now = new Date();
            const timeStr = now.toLocaleTimeString();
            const line = document.createElement('div');
            line.className = 'console-line';
            line.innerHTML = `<span class="time">[${timeStr}]</span> <span class="${type}">${message}</span>`;
            consoleBox.appendChild(line);
            consoleBox.scrollTop = consoleBox.scrollHeight;
            if (consoleBox.children.length > 100) consoleBox.removeChild(consoleBox.children[0]);
        }

        function setMode(mode) {
            currentMode = mode;
            document.getElementById('normalModeBtn').classList.remove('active');
            document.getElementById('smartModeBtn').classList.remove('active');
            if (mode === 'normal') {
                document.getElementById('normalModeBtn').classList.add('active');
                logToConsole('🔄 Switched to NORMAL mode (continuous spam)', 'info');
            } else {
                document.getElementById('smartModeBtn').classList.add('active');
                logToConsole('🧠 Switched to SMART mode (auto start/stop based on status)', 'smart');
            }
        }

        async function loadAutoUids() {
            try {
                const response = await fetch('/api/auto-uids');
                const data = await response.json();
                if (data.success && data.uids) {
                    document.getElementById('autoUidsText').value = data.uids.join('\\n');
                }
            } catch (error) { console.error('Error:', error); }
        }

        async function saveAutoUids() {
            const text = document.getElementById('autoUidsText').value;
            const uids = text.split('\\n').filter(line => line.trim() && /^\\d+$/.test(line.trim())).map(l => l.trim());
            
            try {
                const response = await fetch('/api/auto-uids', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uids: uids })
                });
                const data = await response.json();
                if (data.success) {
                    logToConsole(`✅ Saved ${uids.length} UIDs to auto_uid.txt`, 'success');
                }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }

        async function startAutoSpam() {
            try {
                const response = await fetch('/api/start-auto', { method: 'POST' });
                const data = await response.json();
                if (data.success) {
                    logToConsole(`🧠 ${data.message}`, 'smart');
                    refreshStatus();
                } else {
                    logToConsole(`❌ ${data.message}`, 'error');
                }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }

        async function stopAutoSpam() {
            try {
                const response = await fetch('/api/stop-auto', { method: 'POST' });
                const data = await response.json();
                if (data.success) {
                    logToConsole(`✅ ${data.message}`, 'success');
                    refreshStatus();
                }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }

        async function checkAndStartSmart() {
            const uid = document.getElementById('startUid').value.trim();
            if (!uid) { logToConsole('❌ Please enter target UID!', 'error'); return; }
            if (!/^\\d+$/.test(uid)) { logToConsole('❌ UID must contain only numbers!', 'error'); return; }
            
            logToConsole(`🔍 Checking status for UID: ${uid}...`, 'info');
            
            try {
                const response = await fetch('/api/check-status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uid: uid })
                });
                const data = await response.json();
                if (data.success) {
                    const status = data.data;
                    logToConsole(`📊 Status for ${uid}: ${status.status} | Online: ${status.is_online} | Mode: ${status.mode}`, 'smart');
                    
                    if (status.is_online && status.status !== 'INGAME' && status.status !== 'MATCHMAKING') {
                        logToConsole(`🎯 Target is available! Starting smart monitoring...`, 'success');
                        await startSmartSpam(uid);
                    } else {
                        logToConsole(`⏸️ Target is ${status.status}. Smart monitor will start and wait for availability.`, 'warning');
                        await startSmartSpam(uid);
                    }
                }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }

        async function startSmartSpam(uid) {
            try {
                const response = await fetch('/api/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uid: uid, smart: true })
                });
                const data = await response.json();
                if (data.success) {
                    logToConsole(`🧠 ${data.message}`, 'smart');
                    document.getElementById('startUid').value = '';
                    refreshStatus();
                } else {
                    logToConsole(`❌ ${data.message}`, 'error');
                }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }

        async function startSpam() {
            const uid = document.getElementById('startUid').value.trim();
            if (!uid) { logToConsole('❌ Please enter target UID!', 'error'); return; }
            if (!/^\\d+$/.test(uid)) { logToConsole('❌ UID must contain only numbers!', 'error'); return; }

            if (currentMode === 'smart') {
                await startSmartSpam(uid);
            } else {
                logToConsole(`🚀 Starting NORMAL unlimited spam on UID: ${uid}`, 'info');
                try {
                    const response = await fetch('/api/start', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ uid: uid, smart: false })
                    });
                    const data = await response.json();
                    if (data.success) {
                        logToConsole(`✅ ${data.message}`, 'success');
                        document.getElementById('startUid').value = '';
                        refreshStatus();
                    } else {
                        logToConsole(`❌ ${data.message}`, 'error');
                    }
                } catch (error) { logToConsole(`❌ Connection error: ${error.message}`, 'error'); }
            }
        }

        async function stopSpam() {
            const uid = document.getElementById('stopUid').value.trim();
            if (!uid) { logToConsole('❌ Please enter target UID to stop!', 'error'); return; }

            logToConsole(`🛑 Stopping on UID: ${uid}`, 'info');

            try {
                const response = await fetch('/api/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uid: uid, smart: true })
                });
                const data = await response.json();
                if (data.success) {
                    logToConsole(`✅ ${data.message}`, 'success');
                    document.getElementById('stopUid').value = '';
                    refreshStatus();
                } else {
                    logToConsole(`❌ ${data.message}`, 'error');
                }
            } catch (error) { logToConsole(`❌ Connection error: ${error.message}`, 'error'); }
        }

        async function stopAllSpam() {
            if (!confirm('⚠️ Are you sure you want to STOP ALL SPAM and MONITORS?')) return;

            logToConsole(`🛑 Stopping ALL spam and monitors...`, 'info');

            try {
                const response = await fetch('/api/stop-all', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
                const data = await response.json();
                if (data.success) {
                    logToConsole(`✅ ${data.message}`, 'success');
                    refreshStatus();
                } else {
                    logToConsole(`❌ ${data.message}`, 'error');
                }
            } catch (error) { logToConsole(`❌ Connection error: ${error.message}`, 'error'); }
        }

        async function refreshStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                if (data.success && data.data) {
                    const status = data.data;
                    
                    const activeList = document.getElementById('activeSpamList');
                    if (status.active_targets && status.active_targets.length > 0) {
                        document.getElementById('statusText').innerHTML = `<i class="fa-solid fa-bolt"></i> SPAMMING: ${status.active_targets.length} targets`;
                        activeList.innerHTML = status.active_targets.map(target => `
                            <div class="active-item">
                                <div><span class="active-uid">🎯 ${target.uid}</span>
                                <div style="font-size:10px; color:#888;">♾️ UNLIMITED | ${target.elapsed_minutes} min</div></div>
                                <button class="stop-small" onclick="stopFromList('${target.uid}')">STOP</button>
                            </div>
                        `).join('');
                    } else {
                        document.getElementById('statusText').innerHTML = `<i class="fa-solid fa-check"></i> IDLE`;
                        activeList.innerHTML = '<div class="console-line">📭 No active targets</div>';
                    }
                    
                    // Smart monitored list (Updated to show Real Status)
                    const smartList = document.getElementById('smartMonitoredList');
                    if (status.smart_monitored && status.smart_monitored.length > 0) {
                        document.getElementById('smartCount').innerHTML = status.smart_monitored.length;
                        smartList.innerHTML = status.smart_monitored.map(item => `
                            <div class="active-item smart-item">
                                <div><span class="active-uid">🧠 ${item.uid}</span>
                                <div style="font-size:10px; color:#9b59b6; font-weight: bold;">Status: ${item.status || 'CHECKING...'}</div></div>
                                <button class="stop-small" onclick="stopFromList('${item.uid}')">STOP</button>
                            </div>
                        `).join('');
                    } else {
                        document.getElementById('smartCount').innerHTML = '0';
                        smartList.innerHTML = '<div class="console-line">📭 No smart monitored targets</div>';
                    }
                    
                    const accountsList = document.getElementById('accountsList');
                    if (status.accounts_list && status.accounts_list.length > 0) {
                        accountsList.innerHTML = status.accounts_list.map(acc => `<div class="account-item">✅ ${acc}</div>`).join('');
                        if (status.accounts_count > 50) {
                            accountsList.innerHTML += `<div class="account-item">... and ${status.accounts_count - 50} more</div>`;
                        }
                    } else {
                        accountsList.innerHTML = '<div class="console-line">⚠️ No accounts connected</div>';
                    }
                    
                    if (status.auto_active) {
                        logToConsole(`🧠 Smart auto spam active on ${status.auto_uids.length} UIDs from file`, 'smart');
                    }
                }
            } catch (error) { console.error('Status error:', error); }
        }

        async function stopFromList(uid) {
            document.getElementById('stopUid').value = uid;
            await stopSpam();
        }

        // Load auto UIDs on page load
        loadAutoUids();
        
        // Refresh status every 3 seconds
        setInterval(refreshStatus, 3000);
        refreshStatus();

        document.getElementById('startUid').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') startSpam();
        });
        document.getElementById('stopUid').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') stopSpam();
        });
    </script>
</body>
</html>
'''

# ==================== অ্যাকাউন্ট লোড ====================
# ==================== অ্যাকাউন্ট লোড সেকশন ====================
NORMAL_ACCOUNTS = [] # accs.txt (Room Spam Bots)
INVITE_ACCOUNTS = [] # inv.txt (Group Invite Bots)

def load_accounts_from_file(filename):
    """একটি নির্দিষ্ট ফাইল থেকে UID:PASS লোড করার ফাংশন"""
    accounts = []
    try:
        if not os.path.exists(filename):
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# {filename} - Format: UID:PASSWORD\n")
                f.write("# Example: 4575104506:pass123\n")
            return []
            
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    if ":" in line:
                        parts = line.split(":")
                        accounts.append({'id': parts[0].strip(), 'password': parts[1].strip()})
                    else:
                        accounts.append({'id': line.strip(), 'password': ''})
        return accounts
    except Exception as e:
        print(f"{R}❌ Error loading {filename}: {e}{RS}")
        return []

# ২টি ফাইল থেকে আলাদাভাবে লোড করা
NORMAL_ACCOUNTS = load_accounts_from_file("accs.txt")
INVITE_ACCOUNTS = load_accounts_from_file("inv.txt")

print(f"{G}📦 Loaded {len(NORMAL_ACCOUNTS)} Room Bots from accs.txt{RS}")
print(f"{G}📦 Loaded {len(INVITE_ACCOUNTS)} Invite Bots from inv.txt{RS}")

# কম্বাইন্ড লিস্ট (প্যানেলের জন্য)
ACCOUNTS = NORMAL_ACCOUNTS + INVITE_ACCOUNTS



# ==================== FF Client ====================
class FF_CLient():
    def __init__(self, id, password, is_inviter=False): # is_inviter যোগ করা হয়েছে
        self.id = id
        self.password = password
        self.is_inviter = is_inviter # এটি সেভ রাখুন
        self.key = None
        self.iv = None
        self.Get_FiNal_ToKen_0115()

    def Connect_SerVer_OnLine(self, Token, tok, host, port, key, iv, host2, port2):
        try:
            self.AutH_ToKen_0115 = tok    
            self.CliEnts2 = socket.create_connection((host2, int(port2)))
            self.CliEnts2.send(bytes.fromhex(self.AutH_ToKen_0115))
            with connected_clients_lock:
                if self.id not in connected_clients:
                    connected_clients[self.id] = self
                    print(f"{G}✅ Online: {self.id} (Total: {len(connected_clients)}){RS}")
        except Exception as e:
            print(f"{R}❌ Online error {self.id}: {e}{RS}")
            return
        while True:
            try:
                self.DaTa2 = self.CliEnts2.recv(99999)
                if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:
                    self.packet = json.loads(DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}'))
                    self.AutH = self.packet['5']['data']['7']['data']
            except: pass
                                                            
    def Connect_SerVer(self, Token, tok, host, port, key, iv, host2, port2):
        self.AutH_ToKen_0115 = tok    
        self.CliEnts = socket.create_connection((host, int(port)))
        self.CliEnts.send(bytes.fromhex(self.AutH_ToKen_0115))  
        self.DaTa = self.CliEnts.recv(1024)          	        
        threading.Thread(target=self.Connect_SerVer_OnLine, args=(Token, tok, host, port, key, iv, host2, port2)).start()
        try: self.Exemple = xMsGFixinG('12345678')
        except: pass
        self.key = key
        self.iv = iv
        with connected_clients_lock:
            if self.id not in connected_clients:
                connected_clients[self.id] = self
                print(f"{G}✅ Registered: {self.id}{RS}")
        while True:      
            try:
                self.DaTa = self.CliEnts.recv(1024)   
                if len(self.DaTa) == 0 or (hasattr(self, 'DaTa2') and len(self.DaTa2) == 0):
                    try:
                        self.CliEnts.close()
                        if hasattr(self, 'CliEnts2'): self.CliEnts2.close()
                        self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)                    		                    
                    except:
                        try:
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'): self.CliEnts2.close()
                            self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                        except:
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'): self.CliEnts2.close()
                            ResTarT_BoT()	            
            except Exception as e:
                print(f"{R}❌ Connection error {self.id}: {e}{RS}")
                with connected_clients_lock:
                    if self.id in connected_clients: del connected_clients[self.id]
                self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                                    
    def GeT_Key_Iv(self, serialized_data):
        my_message = xKEys.MyMessage()
        my_message.ParseFromString(serialized_data)
        timestamp, key, iv = my_message.field21, my_message.field22, my_message.field23
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv    

    def Guest_GeneRaTe(self, uid, password):
        self.url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        self.headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        self.dataa = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067",
        }
        try:
            self.response = requests.post(self.url, headers=self.headers, data=self.dataa).json()
            self.Access_ToKen, self.Access_Uid = self.response['access_token'], self.response['open_id']
            time.sleep(0.2)
            print(f'{C}🔐 Login: {self.id}{RS}')
            return self.ToKen_GeneRaTe(self.Access_ToKen, self.Access_Uid)
        except Exception as e: 
            print(f"{R}❌ Login error {self.id}: {e}{RS}")
            time.sleep(10)
            return self.Guest_GeneRaTe(uid, password)
                                        
    def GeT_LoGin_PorTs(self, JwT_ToKen, PayLoad, dynamic_url="https://clientbp.ggpolarbear.com"):
        self.UrL = f'{dynamic_url}/GetLoginData'
        self.HeadErs = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JwT_ToKen}',
            'X-Unity-Version': '2022.3.47f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Connection': 'close',
            'Accept-Encoding': 'deflate, gzip',
        }        
        try:
            self.Res = requests.post(self.UrL, headers=self.HeadErs, data=PayLoad, verify=False)
            self.BesTo_data = json.loads(DeCode_PackEt(self.Res.content.hex()))  
            address, address2 = self.BesTo_data['32']['data'], self.BesTo_data['14']['data'] 
            ip, ip2 = address[:len(address) - 6], address2[:len(address2) - 6]
            port, port2 = address[len(address) - 5:], address2[len(address2) - 5:]             
            return ip, port, ip2, port2          
        except Exception as e:
            print(f"{R}❌ Failed to get ports: {e}{RS}")
        return None, None, None, None
        
    def ToKen_GeneRaTe(self, Access_ToKen, Access_Uid):
        self.UrL = "https://loginbp.ggwhitehawk.com/MajorLogin"
        self.HeadErs = {
            'X-Unity-Version': '2022.3.47f1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Host': 'loginbp.ggwhitehawk.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'deflate, gzip'
        }   
        
        self.dT = bytes.fromhex('1a13323032352d31312d32362030313a35313a3238220966726565206669726528013a07312e3132362e314232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010e3137362e32382e3133392e313835aa01026172b201203433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014063363961653230386661643732373338623637346232383437623530613361316466613235643161313966616537343566633736616334613065343134633934f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e8039a8002f003af13f80384078004a78f028804b5ee029004a78f029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b205094f70656e474c455332b805ff01c00504e005be7eea05093372645f7061727479f205704b717348543857393347646347335a6f7a454e6646775648746d377171316552554e6149444e67526f626f7a4942744c4f695943633459367a767670634943787a514632734f453463627974774c7334785a62526e70524d706d5752514b6d654f35766373386e51594268777148374bf805e7e4068806019006019a060134a2060134b2062213521146500e590349510e460900115843395f005b510f685b560a6107576d0f0366')
        
        self.dT = self.dT.replace(b'2025-07-30 14:11:20', str(datetime.now())[:-7].encode())
        self.dT = self.dT.replace(b'c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94', Access_ToKen.encode())
        self.dT = self.dT.replace(b'4306245793de86da425a52caadf21eed', Access_Uid.encode())
        
        try:
            hex_data = self.dT.hex()
            encoded_data = EnC_AEs(hex_data)
            if not all(c in '0123456789abcdefABCDEF' for c in encoded_data):
                encoded_data = hex_data
            self.PaYload = bytes.fromhex(encoded_data)
        except Exception as e:
            print(f"{R}❌ Encoding error: {e}{RS}")
            self.PaYload = self.dT
        
        self.ResPonse = requests.post(self.UrL, headers=self.HeadErs, data=self.PaYload, verify=False)        
        if self.ResPonse.status_code == 200 and len(self.ResPonse.text) > 10:
            try:
                self.BesTo_data = json.loads(DeCode_PackEt(self.ResPonse.content.hex()))
                self.JwT_ToKen = self.BesTo_data['8']['data']           
                self.combined_timestamp, self.key, self.iv = self.GeT_Key_Iv(self.ResPonse.content)
                ip, port, ip2, port2 = self.GeT_LoGin_PorTs(self.JwT_ToKen, self.PaYload)            
                return self.JwT_ToKen, self.key, self.iv, self.combined_timestamp, ip, port, ip2, port2
            except Exception as e:
                print(f"{R}❌ Response parsing error: {e}{RS}")
                time.sleep(5)
                return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
        else:
            print(f"{R}❌ Token generation error, status: {self.ResPonse.status_code}{RS}")
            time.sleep(5)
            return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
      
    def Get_FiNal_ToKen_0115(self):
        try:
            result = self.Guest_GeneRaTe(self.id, self.password)
            if not result:
                print(f"{Y}⚠️ Failed to get token {self.id}, retrying...{RS}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            token, key, iv, Timestamp, ip, port, ip2, port2 = result
            
            if not all([ip, port, ip2, port2]):
                print(f"{Y}⚠️ Failed to get ports {self.id}, retrying...{RS}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            self.JwT_ToKen = token        
            try:
                self.AfTer_DeC_JwT = jwt.decode(token, options={"verify_signature": False})
                self.AccounT_Uid = self.AfTer_DeC_JwT.get('account_id')
                self.EncoDed_AccounT = hex(self.AccounT_Uid)[2:]
                self.HeX_VaLue = DecodE_HeX(Timestamp)
                self.TimE_HEx = self.HeX_VaLue
                self.JwT_ToKen_ = token.encode().hex()
                print(f'{C}🆔 Account UID: {self.AccounT_Uid}{RS}')
            except Exception as e:
                print(f"{R}❌ Token decode error {self.id}: {e}{RS}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            try:
                self.Header = hex(len(EnC_PacKeT(self.JwT_ToKen_, key, iv)) // 2)[2:]
                length = len(self.EncoDed_AccounT)
                self.__ = '00000000'
                if length == 9: self.__ = '0000000'
                elif length == 8: self.__ = '00000000'
                elif length == 10: self.__ = '000000'
                elif length == 7: self.__ = '000000000'
                self.Header = f'0115{self.__}{self.EncoDed_AccounT}{self.TimE_HEx}00000{self.Header}'
                self.FiNal_ToKen_0115 = self.Header + EnC_PacKeT(self.JwT_ToKen_, key, iv)
            except Exception as e:
                print(f"{R}❌ Final token error {self.id}: {e}{RS}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            self.AutH_ToKen = self.FiNal_ToKen_0115
            self.Connect_SerVer(self.JwT_ToKen, self.AutH_ToKen, ip, port, key, iv, ip2, port2)        
            return self.AutH_ToKen, key, iv
            
        except Exception as e:
            print(f"{R}❌ {self.id} connection failed: {e}{RS}")
            time.sleep(10)
            return self.Get_FiNal_ToKen_0115()

# ==================== অ্যাকাউন্ট রান করার ফাংশন ====================
def start_account(account, is_inviter):
    """বট আইডি লগইন করার ফাংশন"""
    try:
        type_str = "INVITE" if is_inviter else "ROOM"
        print(f"{G}🚀 Starting {type_str} Bot: {account['id']}{RS}")
        FF_CLient(account['id'], account['password'], is_inviter=is_inviter)
    except Exception as e:
        print(f"{R}❌ {account['id']} login failed: {e}. Retrying...{RS}")
        time.sleep(5)
        start_account(account, is_inviter)

def run_accounts():
    """সবগুলো অ্যাকাউন্টকে থ্রেডে রান করা"""
    # Room Bots শুরু করা (accs.txt)
    for account in NORMAL_ACCOUNTS:
        Thread(target=start_account, args=(account, False), daemon=True).start()
        time.sleep(0.2)
        
    # Invite Bots শুরু করা (inv.txt)
    for account in INVITE_ACCOUNTS:
        Thread(target=start_account, args=(account, True), daemon=True).start()
        time.sleep(0.2)

# ==================== মেইন ====================
def main():
    # ১. auto_uid.txt থেকে টার্গেট লোড করা
    load_auto_uids()
    
    # ২. অ্যাকাউন্টগুলো লগইন করা শুরু করা
    print(f"{C}📡 Logging into all accounts (accs.txt & inv.txt)...{RS}")
    Thread(target=run_accounts, daemon=True).start()
    
    # ৩. ৭ মিনিটের অটো রিফ্রেশ টাইমার চালু করা
    start_auto_refresh()
    
    # ৪. যদি auto_uid.txt তে আইডি থাকে, তবে স্মার্ট মনিটর অটো চালু করা
    if auto_uids:
        print(f"{G}🧠 Auto-starting SMART monitor on {len(auto_uids)} UIDs from auto_uid.txt{RS}")
        for uid in auto_uids:
            start_smart_monitor(uid)
        global auto_spam_active
        auto_spam_active = True
    
    # ৫. পোর্ট সেটআপ
    port = int(os.environ.get("PORT", 5002))
    
    print(f"""
    {C}{BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║          🧠 NIROB SPAM SMART EDITION 🧠                     ║
    ║                                                              ║
    ║     ✅ INVITE BOTS  : Loaded from inv.txt                  ║
    ║     ✅ ROOM BOTS    : Loaded from accs.txt                ║
    ║     ✅ SMART MONITOR: Auto Status Tracking                 ║
    ║     ✅ WEB PANEL    : http://127.0.0.1:{port}                    ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    {RS}
    """)
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

if __name__ == "__main__":
    # Install required package for protobuf decoding if not present
    try:
        import aiohttp
    except ImportError:
        os.system("pip install aiohttp")
    
    try:
        from protobuf_decoder.protobuf_decoder import Parser
    except ImportError:
        os.system("pip install protobuf-decoder")
    
    main()
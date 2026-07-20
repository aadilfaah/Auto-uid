import os, sys, time, json, ssl, socket, threading, asyncio, base64, binascii, re, jwt, pickle
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Thread, Lock
from collections import deque
from flask import Flask, request, jsonify, render_template_string
import random

import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.timestamp_pb2 import Timestamp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==================== IND SERVER CONFIGURATION ====================
IND_LOGIN_URL = "https://loginbp.ggpolarbear.com/"
IND_SERVER_URL = "https://client.ind.freefiremobile.com"

# ==================== GLOBAL VARIABLES ====================
connected_clients = {}
connected_clients_lock = Lock()
active_targets = {}
active_targets_lock = Lock()
target_active = {}
spam_active = True
live_logs = []
MAX_LOGS = 100
logs_lock = Lock()

ROOM_BOTS = []
INVITE_BOTS = []
ALL_BOTS = []

saved_uids = []
saved_uids_lock = Lock()

C = "\033[96m"
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
RS = "\033[0m"
BOLD = "\033[1m"

# ==================== SPAM CONFIGURATION ====================
PACKETS_PER_BURST = 10
PACKET_DELAY = 0.005
BOT_SWITCH_DELAY = 0.001

def add_log(message, log_type="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = {"time": timestamp, "message": message, "type": log_type}
    with logs_lock:
        live_logs.append(log_entry)
        if len(live_logs) > MAX_LOGS:
            live_logs.pop(0)
    print(f"[{timestamp}] {message}")

# ==================== CRYPTO FUNCTIONS ====================
Key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
Iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def EnC_AEs(HeX):
    cipher = AES.new(Key, AES.MODE_CBC, Iv)
    return cipher.encrypt(pad(bytes.fromhex(HeX), AES.block_size)).hex()

def EnC_PacKeT(HeX, K, V):
    return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()

def EnC_Uid(H, Tp):
    e, H = [], int(H)
    while H:
        e.append((H & 0x7F) | (0x80 if H > 0x7F else 0))
        H >>= 7
    return bytes(e).hex() if Tp == 'Uid' else None

def EnC_Vr(N):
    if N < 0:
        return ''
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N:
            BesTo |= 0x80
        H.append(BesTo)
        if not N:
            break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

def DecodE_HeX(H):
    R = hex(H)
    F = str(R)[2:]
    if len(F) == 1:
        F = "0" + F
        return F
    else:
        return F

def GeneRaTePk(Pk, N, K, V):
    PkEnc = EnC_PacKeT(Pk, K, V)
    _ = DecodE_HeX(int(len(PkEnc) // 2))
    if len(_) == 2:
        HeadEr = N + "000000"
    elif len(_) == 3:
        HeadEr = N + "00000"
    elif len(_) == 4:
        HeadEr = N + "0000"
    elif len(_) == 5:
        HeadEr = N + "000"
    else:
        HeadEr = N + "000000"
    return bytes.fromhex(HeadEr + _ + PkEnc)

# ==================== IND SERVER SPECIFIC PACKETS ====================
def OpEnSq(K, V):
    fields = {1: 1, 2: {2: "\u0001", 3: 1, 4: 1, 5: "en", 9: 1, 11: 1, 13: 1, 14: {2: 5756, 6: 11, 8: "1.111.5", 9: 2, 10: 4}}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0514', K, V)

def cHSq(Nu, Uid, K, V):
    fields = {1: 17, 2: {1: int(Uid), 2: 1, 3: int(Nu - 1), 4: 62, 5: "\u001a", 8: 5, 13: 329}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0514', K, V)

def SEnd_InV(Nu, Uid, K, V):
    fields = {1: 2, 2: {1: int(Uid), 2: "🇮🇳 I AM FIX 🇮🇳", 4: int(Nu)}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0514', K, V)

def ExiT(idT, K, V):
    fields = {1: 7, 2: {1: int(11037044965)}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0514', K, V)

def spmroom(K, V, uid):
    fields = {1: 22, 2: {1: int(uid)}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0E14', K, V)

def openroom(K, V):
    fields = {
        1: 2,
        2: {
            1: 1, 2: 15, 3: 5, 4: "[c][FF0000]🇮🇳 I AM FIX 🇮🇳",
            5: "1", 6: 12, 7: 1, 8: 1, 9: 1, 11: 1, 12: 2,
            14: 36981056, 15: {1: "IDC3", 2: 126, 3: "ME"},
            16: "\u0001\u0003\u0004\u0007\t\n\u000b\u0012\u000f\u000e\u0016\u0019\u001a \u001d",
            18: 2368584, 27: 1, 34: "\u0000\u0001", 40: "en", 48: 1,
            49: {1: 21}, 50: {1: 36981056, 2: 2368584, 5: 2}
        }
    }
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0E14', K, V)

# ==================== ACCOUNT LOADER ====================
def load_accounts_from_file(filename):
    accounts = []
    try:
        if not os.path.exists(filename):
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# {filename} - Format: UID:PASSWORD\n")
                f.write("# Example: 4575104506:password123\n")
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

def reload_accounts():
    global ROOM_BOTS, INVITE_BOTS, ALL_BOTS
    ROOM_BOTS = load_accounts_from_file("accs.txt")
    INVITE_BOTS = load_accounts_from_file("inv.txt")
    ALL_BOTS = []
    for bot in ROOM_BOTS:
        bot['is_inviter'] = False
        ALL_BOTS.append(bot)
    for bot in INVITE_BOTS:
        bot['is_inviter'] = True
        ALL_BOTS.append(bot)
    add_log(f"🇮🇳 IND SERVER: Loaded {len(ROOM_BOTS)} Room Bots + {len(INVITE_BOTS)} Invite Bots = {len(ALL_BOTS)} total", "success")
    return ALL_BOTS

# ==================== SEND SPAM PACKET (IND SERVER) ====================
def send_single_packet(bot_client, target_id):
    try:
        if not hasattr(bot_client, 'CliEnts2') or bot_client.CliEnts2 is None:
            return False
        
        if bot_client.is_inviter:
            try:
                p1 = OpEnSq(bot_client.key, bot_client.iv)
                bot_client.CliEnts2.send(p1)
                time.sleep(0.002)
                p2 = cHSq(5, target_id, bot_client.key, bot_client.iv)
                bot_client.CliEnts2.send(p2)
                time.sleep(0.002)
                p3 = SEnd_InV(5, target_id, bot_client.key, bot_client.iv)
                bot_client.CliEnts2.send(p3)
                time.sleep(0.002)
                p4 = ExiT(target_id, bot_client.key, bot_client.iv)
                bot_client.CliEnts2.send(p4)
                return True
            except:
                return False
        else:
            try:
                open_pkt = openroom(bot_client.key, bot_client.iv)
                if open_pkt:
                    bot_client.CliEnts2.send(open_pkt)
                spam_pkt = spmroom(bot_client.key, bot_client.iv, target_id)
                if spam_pkt:
                    bot_client.CliEnts2.send(spam_pkt)
                    return True
            except:
                return False
        return False
    except:
        return False

# ==================== CONTINUOUS SPAM ENGINE ====================
def continuous_spam_worker():
    global spam_active
    bot_index = 0
    total_bots = len(ALL_BOTS)
    
    if total_bots == 0:
        add_log("❌ No bots available! Add bots to accs.txt or inv.txt", "error")
        return
    
    add_log(f"🇮🇳 IND SERVER SPAM ENGINE STARTED with {total_bots} bots", "attack")
    add_log(f"⚡ I AM FIX MODE ACTIVE | 10 Packets/Bot | 5ms Delay | NON-STOP", "info")
    
    while spam_active:
        with active_targets_lock:
            current_targets = list(active_targets.keys())
        
        if not current_targets:
            time.sleep(0.1)
            continue
        
        for target_id in current_targets:
            if not spam_active:
                break
            
            for packet_num in range(PACKETS_PER_BURST):
                if not spam_active or target_id not in target_active:
                    break
                
                bot = ALL_BOTS[bot_index % total_bots]
                
                with connected_clients_lock:
                    bot_client = connected_clients.get(bot['id'])
                
                if bot_client and hasattr(bot_client, 'CliEnts2') and bot_client.CliEnts2:
                    success = send_single_packet(bot_client, target_id)
                    if success:
                        add_log(f"⚡ Bot {bot['id']} sent packet {packet_num+1}/10 to {target_id} [🇮🇳 IND SERVER]", "attack")
                    else:
                        add_log(f"⚠️ Bot {bot['id']} failed on {target_id}, skipping", "warning")
                
                bot_index += 1
                time.sleep(PACKET_DELAY)
            
            bot_index += 1

def start_spam_engine():
    thread = Thread(target=continuous_spam_worker, daemon=True)
    thread.start()
    add_log("🔄 IND SERVER Spam engine thread started", "info")

# ==================== TARGET MANAGEMENT ====================
def start_target_spam(target_id, target_type="single"):
    with active_targets_lock:
        if target_id in active_targets:
            return False, f"Already spamming on: {target_id}"
        active_targets[target_id] = {'type': target_type, 'start_time': datetime.now()}
        target_active[target_id] = True
    add_log(f"✅ Started {target_type.upper()} spam on: {target_id} [🇮🇳 IND SERVER]", "success")
    return True, f"Started {target_type} spam on: {target_id}"

def stop_target_spam(target_id):
    with active_targets_lock:
        if target_id not in active_targets:
            return False, f"No active spam on: {target_id}"
        target_active[target_id] = False
        del active_targets[target_id]
    add_log(f"🛑 Stopped spam on: {target_id}", "stop")
    return True, f"Spam stopped on: {target_id}"

def stop_all_spam():
    global spam_active
    with active_targets_lock:
        targets = list(active_targets.keys())
        for target_id in targets:
            target_active[target_id] = False
        active_targets.clear()
    add_log(f"🛑 Stopped all spam ({len(targets)} targets)", "stop")
    return True, f"Stopped all spam ({len(targets)} targets)"

def save_and_spam(uids_text):
    global saved_uids
    uids = []
    if ',' in uids_text:
        uids = [uid.strip() for uid in uids_text.split(',') if uid.strip().isdigit()]
    else:
        uids = [uid.strip() for uid in uids_text.split('\n') if uid.strip().isdigit()]
    
    if not uids:
        return False, "Invalid UID format", 0
    
    try:
        with open("auto_uid.txt", "w", encoding="utf-8") as f:
            f.write("# Saved UIDs - One per line\n")
            for uid in uids:
                f.write(f"{uid}\n")
    except Exception as e:
        add_log(f"Failed to save UIDs: {e}", "error")
    
    with saved_uids_lock:
        saved_uids = uids
    
    success_count = 0
    for uid in uids:
        success, _ = start_target_spam(uid, "saved")
        if success:
            success_count += 1
    
    return True, f"Saved {len(uids)} UIDs. Started spam on {success_count} targets", len(uids)

def get_status():
    targets_info = []
    with active_targets_lock:
        for target_id, info in active_targets.items():
            start_time = info.get('start_time')
            elapsed_minutes = int((datetime.now() - start_time).total_seconds() / 60) if start_time else 0
            targets_info.append({'uid': target_id, 'type': info.get('type', 'single'), 'elapsed_minutes': elapsed_minutes})
    
    with connected_clients_lock:
        accounts_count = len(connected_clients)
        accounts_list = list(connected_clients.keys())
        room_bots_online = []
        invite_bots_online = []
        for uid in accounts_list:
            client = connected_clients.get(uid)
            if client and hasattr(client, 'is_inviter'):
                if client.is_inviter:
                    invite_bots_online.append(uid)
                else:
                    room_bots_online.append(uid)
    
    with saved_uids_lock:
        saved_list = saved_uids.copy()
    
    with logs_lock:
        recent_logs = live_logs[-35:].copy()
    
    return {
        'active_targets': targets_info,
        'active_count': len(targets_info),
        'accounts_count': accounts_count,
        'room_bots_online': room_bots_online,
        'invite_bots_online': invite_bots_online,
        'room_bots_total': len(ROOM_BOTS),
        'invite_bots_total': len(INVITE_BOTS),
        'saved_uids': saved_list,
        'live_logs': recent_logs
    }

# ==================== FLASK ROUTES ====================
@app.route('/')
def splash():
    return render_template_string(SPLASH_HTML)

@app.route('/main')
def main_page():
    return render_template_string(MAIN_HTML)

@app.route('/api/save-and-spam', methods=['POST'])
def api_save_and_spam():
    data = request.get_json()
    uids_text = data.get('uids', '').strip()
    if not uids_text:
        return jsonify({'success': False, 'message': 'At least one UID is required'})
    success, message, count = save_and_spam(uids_text)
    return jsonify({'success': success, 'message': message, 'saved_count': count})

@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.get_json()
    target_id = data.get('uid', '').strip()
    if not target_id:
        return jsonify({'success': False, 'message': 'UID is required'})
    if not target_id.isdigit():
        return jsonify({'success': False, 'message': 'UID must contain only numbers'})
    success, message = start_target_spam(target_id, "single")
    return jsonify({'success': success, 'message': message})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    data = request.get_json()
    target_id = data.get('uid', '').strip()
    if not target_id:
        return jsonify({'success': False, 'message': 'UID is required'})
    success, message = stop_target_spam(target_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/stop-all', methods=['POST'])
def api_stop_all():
    success, message = stop_all_spam()
    return jsonify({'success': success, 'message': message})

@app.route('/api/status', methods=['GET'])
def api_status():
    status = get_status()
    return jsonify({'success': True, 'data': status})

@app.route('/api/accounts', methods=['GET'])
def api_accounts():
    with connected_clients_lock:
        room_online = []
        invite_online = []
        for uid, client in connected_clients.items():
            if hasattr(client, 'is_inviter') and client.is_inviter:
                invite_online.append(uid)
            else:
                room_online.append(uid)
        return jsonify({
            'success': True,
            'room_bots_online': room_online,
            'invite_bots_online': invite_online,
            'room_bots_total': len(ROOM_BOTS),
            'invite_bots_total': len(INVITE_BOTS),
            'total_online': len(connected_clients)
        })

@app.route('/mahir', methods=['GET'])
def mahir_get_endpoint():
    target_id = request.args.get('uid', '').strip()
    if not target_id:
        return jsonify({'success': False, 'message': 'Please provide UID. Example: /mahir?uid=12345678'}), 400
    if not target_id.isdigit():
        return jsonify({'success': False, 'message': 'Invalid UID! Use numbers only.'}), 400
    success, message = start_target_spam(target_id, "single")
    return jsonify({'success': success, 'target_uid': target_id, 'message': message, 'status': '🇮🇳 I AM FIX - IND SERVER 🇮🇳'})

# ==================== SPLASH HTML ====================
SPLASH_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🇮🇳 I AM FIX - IND SERVER 🇮🇳</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh;
            background: linear-gradient(135deg, #000000 0%, #0a0a2a 50%, #1a0033 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Courier New', monospace;
            overflow: hidden;
        }
        .splash-container { text-align: center; animation: fadeIn 1s ease; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .flag-badge { font-size: 3rem; margin-bottom: 20px; animation: bounce 1s ease infinite; }
        @keyframes bounce { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
        .glow-text {
            font-size: 3.5rem;
            font-weight: 900;
            letter-spacing: 8px;
            background: linear-gradient(135deg, #ff9933, #ffffff, #138808);
            background-size: 200% auto;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradientShift 3s linear infinite;
            margin-bottom: 20px;
            min-height: 100px;
        }
        @keyframes gradientShift { 0% { background-position: 0% center; } 100% { background-position: 200% center; } }
        .subtitle { color: rgba(255,153,51,0.8); font-size: 1rem; margin-bottom: 30px; letter-spacing: 2px; }
        .enter-btn {
            background: linear-gradient(90deg, #ff9933, #138808);
            border: none; padding: 15px 50px; font-size: 1.3rem; font-weight: bold;
            color: white; border-radius: 50px; cursor: pointer; transition: all 0.3s;
            animation: pulse 2s ease-in-out infinite; opacity: 0; margin-top: 20px;
        }
        .enter-btn.show { opacity: 1; }
        .enter-btn:hover { transform: scale(1.05); box-shadow: 0 0 40px rgba(255,153,51,0.6); }
        @keyframes pulse { 0%,100% { box-shadow: 0 0 20px rgba(255,153,51,0.3); } 50% { box-shadow: 0 0 50px rgba(255,153,51,0.6); } }
        .ind-badge { color: #ff9933; font-size: 0.9rem; margin-top: 20px; letter-spacing: 3px; }
        .particle {
            position: fixed; width: 2px; height: 2px; background: #ff9933;
            border-radius: 50%; opacity: 0.3; animation: floatParticle 15s linear infinite;
        }
        @keyframes floatParticle {
            0% { transform: translateY(100vh) rotate(0deg); opacity: 0; }
            10% { opacity: 0.3; } 90% { opacity: 0.3; }
            100% { transform: translateY(-100vh) rotate(360deg); opacity: 0; }
        }
    </style>
</head>
<body>
    <div class="splash-container">
        <div class="flag-badge">🇮🇳</div>
        <div class="glow-text" id="typewriterText"></div>
        <div class="subtitle">⚡ INDIA SERVER ULTIMATE EDITION ⚡</div>
        <button class="enter-btn" id="enterBtn" onclick="goToMain()">⚡ ENTER IND SERVER ⚡</button>
        <div class="ind-badge">🇮🇳 I AM FIX | NON-STOP SPAM | INDIA SERVER 🇮🇳</div>
    </div>
    <script>
        const text = "I AM FIX";
        let index = 0;
        const typewriterElement = document.getElementById('typewriterText');
        const enterBtn = document.getElementById('enterBtn');
        function typeWriter() {
            if (index < text.length) {
                typewriterElement.innerHTML += text.charAt(index);
                index++;
                setTimeout(typeWriter, 150);
            } else { enterBtn.classList.add('show'); }
        }
        typeWriter();
        function goToMain() { window.location.href = '/main'; }
        for (let i = 0; i < 50; i++) {
            const particle = document.createElement('div');
            particle.classList.add('particle');
            particle.style.left = Math.random() * 100 + '%';
            particle.style.animationDelay = Math.random() * 15 + 's';
            particle.style.animationDuration = 10 + Math.random() * 10 + 's';
            particle.style.background = Math.random() > 0.5 ? '#ff9933' : '#138808';
            document.body.appendChild(particle);
        }
    </script>
</body>
</html>
'''

# ==================== MAIN HTML ====================
MAIN_HTML = '''
<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🇮🇳 I AM FIX - IND SERVER SPAM 🇮🇳</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;800;900&family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #0a0a2a 50%, #1a0033 100%);
            min-height: 100vh;
            overflow-x: hidden;
        }
        .bg-animation { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -2; background: radial-gradient(ellipse at center, rgba(255,153,51,0.05) 0%, transparent 70%); }
        .glow-orb { position: fixed; width: 500px; height: 500px; border-radius: 50%; background: radial-gradient(circle, rgba(255,153,51,0.08) 0%, transparent 70%); animation: float 20s ease-in-out infinite; z-index: -1; }
        .glow-orb:nth-child(1) { top: -200px; left: -200px; }
        .glow-orb:nth-child(2) { bottom: -300px; right: -200px; animation-delay: -10s; background: radial-gradient(circle, rgba(19,136,8,0.08) 0%, transparent 70%); }
        @keyframes float { 0%,100% { transform: translate(0,0) scale(1); } 50% { transform: translate(50px,50px) scale(1.1); } }
        #matrixCanvas { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; opacity: 0.15; }
        .app-container { max-width: 750px; margin: 0 auto; padding: 20px; }
        .welcome-card {
            background: rgba(10,15,30,0.8); backdrop-filter: blur(15px); border-radius: 30px;
            padding: 25px; margin-bottom: 25px; border: 1px solid rgba(255,153,51,0.3);
            box-shadow: 0 0 40px rgba(255,153,51,0.1); transition: all 0.3s;
        }
        .welcome-card:hover { border-color: rgba(255,153,51,0.6); box-shadow: 0 0 60px rgba(255,153,51,0.2); }
        .welcome-title { text-align: center; font-family: 'Orbitron', monospace; font-size: 2rem; background: linear-gradient(135deg, #ff9933, #ffffff, #138808); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 20px; }
        .ind-badge-header { text-align: center; background: rgba(255,153,51,0.2); border-radius: 30px; padding: 8px; margin-bottom: 15px; color: #ff9933; font-weight: bold; }
        .warning-box { background: rgba(255,51,102,0.1); border-left: 3px solid #ff3366; padding: 12px; margin: 15px 0; border-radius: 10px; }
        .warning-box h4 { color: #ff3366; margin-bottom: 5px; }
        .warning-box p { color: #aaa; font-size: 0.75rem; }
        .howto-box { background: rgba(0,212,255,0.05); border-radius: 12px; padding: 12px; margin-top: 12px; }
        .howto-box h4 { color: #00d4ff; margin-bottom: 8px; font-size: 0.85rem; }
        .howto-box p { color: #aaa; font-size: 0.7rem; margin: 4px 0; }
        .feature-list { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
        .feature-badge { background: rgba(255,153,51,0.1); border: 1px solid rgba(255,153,51,0.3); border-radius: 20px; padding: 4px 12px; font-size: 0.65rem; color: #ff9933; }
        .vip-card { background: rgba(15,20,35,0.7); backdrop-filter: blur(12px); border-radius: 25px; padding: 22px; margin-bottom: 20px; border: 1px solid rgba(0,212,255,0.2); transition: all 0.3s; }
        .vip-card:hover { border-color: rgba(0,212,255,0.5); transform: translateY(-2px); }
        .card-header { display: flex; align-items: center; gap: 12px; margin-bottom: 18px; }
        .card-icon { width: 45px; height: 45px; background: linear-gradient(135deg, #ff993320, #13880820); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; color: #ff9933; }
        .card-title { font-size: 1.1rem; font-weight: 700; color: white; }
        .card-subtitle { font-size: 0.6rem; color: #888; }
        .vip-input { width: 100%; background: rgba(5,8,20,0.9); border: 1px solid rgba(255,153,51,0.3); border-radius: 14px; padding: 14px; color: white; font-size: 0.9rem; font-family: monospace; resize: vertical; }
        .vip-input:focus { outline: none; border-color: #ff9933; box-shadow: 0 0 12px rgba(255,153,51,0.2); }
        .vip-input-small { background: rgba(5,8,20,0.9); border: 1px solid rgba(255,153,51,0.3); border-radius: 14px; padding: 12px; color: white; font-size: 0.9rem; font-family: monospace; width: 100%; }
        .vip-btn { padding: 12px 20px; border: none; border-radius: 14px; font-weight: 700; font-size: 0.9rem; cursor: pointer; transition: all 0.3s; display: inline-flex; align-items: center; justify-content: center; gap: 8px; }
        .vip-btn-primary { background: linear-gradient(90deg, #00d4ff, #0088ff); color: white; }
        .vip-btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0,212,255,0.4); }
        .vip-btn-danger { background: linear-gradient(90deg, #ff3366, #cc0044); color: white; }
        .vip-btn-warning { background: linear-gradient(90deg, #ff9933, #138808); color: white; }
        .vip-btn-success { background: linear-gradient(90deg, #00ff88, #00cc66); color: #000; }
        .vip-btn-outline { background: transparent; border: 1px solid #ff9933; color: #ff9933; }
        .flex-buttons { display: flex; gap: 12px; margin-top: 15px; flex-wrap: wrap; }
        .console { background: #000000cc; border-radius: 14px; padding: 12px; height: 200px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.7rem; }
        .console-line { margin-bottom: 4px; padding: 3px 8px; border-radius: 6px; }
        .console-line .time { color: #00d4ff; margin-right: 10px; }
        .console-line.success { color: #00ff88; background: rgba(0,255,136,0.05); }
        .console-line.error { color: #ff3366; background: rgba(255,51,102,0.05); }
        .console-line.attack { color: #ff9933; background: rgba(255,153,51,0.05); }
        .console-line.stop { color: #ffd700; background: rgba(255,215,0,0.05); }
        .console-line.info { color: #00d4ff; background: rgba(0,212,255,0.05); }
        .status-badge { background: rgba(0,255,136,0.1); border: 1px solid #00ff88; border-radius: 14px; padding: 10px; margin-top: 12px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; }
        .status-dot { width: 8px; height: 8px; background: #00ff88; border-radius: 50%; animation: pulse 1.5s infinite; display: inline-block; }
        @keyframes pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(1.2); } }
        .active-list, .accounts-list { max-height: 200px; overflow-y: auto; }
        .active-item { background: rgba(255,153,51,0.08); border-left: 3px solid #ff9933; padding: 10px; margin: 6px 0; border-radius: 10px; display: flex; justify-content: space-between; align-items: center; }
        .active-uid { font-family: monospace; font-weight: bold; color: #ff9933; font-size: 0.85rem; }
        .stop-small { background: #ff3366; border: none; padding: 4px 14px; border-radius: 8px; color: white; cursor: pointer; font-size: 0.65rem; font-weight: bold; }
        .account-item { background: rgba(0,212,255,0.06); padding: 6px 12px; margin: 4px 0; border-radius: 8px; font-family: monospace; font-size: 0.7rem; display: flex; justify-content: space-between; align-items: center; }
        .account-type-room { color: #00d4ff; }
        .account-type-invite { color: #ff9933; }
        .footer { text-align: center; margin-top: 20px; padding: 15px; border-top: 1px solid rgba(255,153,51,0.2); }
        .copyright { color: #555; font-size: 0.65rem; }
        .refresh-info { background: rgba(255,153,51,0.08); border-radius: 10px; padding: 6px; text-align: center; font-size: 0.6rem; margin-top: 8px; }
        .live-dot { width: 6px; height: 6px; background: #ff3366; border-radius: 50%; animation: livePulse 1s infinite; display: inline-block; }
        @keyframes livePulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
    </style>
</head>
<body>
    <div class="bg-animation"></div>
    <div class="glow-orb"></div>
    <div class="glow-orb"></div>
    <canvas id="matrixCanvas"></canvas>
    <div class="app-container">
        <div class="welcome-card">
            <div class="ind-badge-header">🇮🇳 INDIA SERVER | I AM FIX MODE 🇮🇳</div>
            <div class="welcome-title">⚡ I AM FIX ⚡</div>
            <div class="warning-box">
                <h4><i class="fas fa-exclamation-triangle"></i> ⚠️ সতর্কতা ⚠️</h4>
                <p>এই টুলটি শুধুমাত্র শিক্ষাগত উদ্দেশ্যে তৈরি। অন্যের ক্ষতি করতে ব্যবহার করলে আপনার একাউন্ট ব্যান হবে। সমস্ত দায়িত্ব ব্যবহারকারীর।</p>
            </div>
            <div class="howto-box">
                <h4><i class="fas fa-book-open"></i> 📖 কিভাবে ব্যবহার করবেন:</h4>
                <p>① <strong>SAVE UID</strong> বক্সে UID লিখে <strong>"SAVE & SPAM"</strong> চাপুন → UID গুলো সেভ হবে এবং সাথে সাথে স্প্যাম শুরু হবে</p>
                <p>② <strong>SINGLE TARGET</strong> বক্সে UID লিখে <strong>"START SPAM"</strong> চাপুন → একটি মাত্র টার্গেটে স্প্যাম শুরু হবে</p>
                <p>③ স্প্যাম বন্ধ করতে <strong>"STOP"</strong> বা <strong>"STOP ALL"</strong> চাপুন</p>
                <p>④ URL দিয়েও স্প্যাম: <strong>/mahir?uid=12345678</strong></p>
            </div>
            <div class="feature-list">
                <span class="feature-badge"><i class="fas fa-globe"></i> IND SERVER</span>
                <span class="feature-badge"><i class="fas fa-tachometer-alt"></i> 5ms Delay</span>
                <span class="feature-badge"><i class="fas fa-infinity"></i> Non-Stop</span>
                <span class="feature-badge"><i class="fas fa-robot"></i> Rotating Bots</span>
                <span class="feature-badge"><i class="fas fa-bolt"></i> I AM FIX</span>
            </div>
        </div>
        <div class="vip-card">
            <div class="card-header">
                <div class="card-icon"><i class="fas fa-save"></i></div>
                <div><div class="card-title">💾 SAVE UID</div><div class="card-subtitle">একাধিক UID কমা বা নিউলাইন দিয়ে লিখুন</div></div>
            </div>
            <textarea id="saveUids" class="vip-input" rows="3" placeholder="1234567890, 9876543210, 5555555555"></textarea>
            <button class="vip-btn vip-btn-success" onclick="saveAndSpam()" style="width:100%; margin-top:12px;"><i class="fas fa-save"></i> 💾 SAVE & SPAM</button>
        </div>
        <div class="vip-card">
            <div class="card-header">
                <div class="card-icon"><i class="fas fa-bullseye"></i></div>
                <div><div class="card-title">🎯 SINGLE TARGET</div><div class="card-subtitle">একটি মাত্র UID তে স্প্যাম</div></div>
            </div>
            <input type="text" id="singleUid" class="vip-input-small" style="width:100%;" placeholder="Enter Target UID" inputmode="numeric">
            <div class="flex-buttons">
                <button class="vip-btn vip-btn-primary" onclick="startSingleSpam()"><i class="fas fa-play"></i> 🎯 START SPAM</button>
                <button class="vip-btn vip-btn-danger" onclick="stopSingleSpam()"><i class="fas fa-stop"></i> 🛑 STOP</button>
            </div>
        </div>
        <div class="vip-card">
            <div class="card-header">
                <div class="card-icon"><i class="fas fa-sliders-h"></i></div>
                <div><div class="card-title">কন্ট্রোল প্যানেল</div><div class="card-subtitle">রিফ্রেশ ও স্প্যাম কন্ট্রোল</div></div>
            </div>
            <div class="flex-buttons">
                <button class="vip-btn vip-btn-outline" onclick="manualRefresh()"><i class="fas fa-sync-alt"></i> 🔄 REFRESH</button>
                <button class="vip-btn vip-btn-warning" onclick="stopAllSpam()"><i class="fas fa-stop-circle"></i> ⛔ STOP ALL</button>
            </div>
        </div>
        <div class="vip-card">
            <div class="card-header">
                <div class="card-icon"><i class="fas fa-list"></i></div>
                <div><div class="card-title">📋 অ্যাক্টিভ টার্গেট</div><div class="card-subtitle">স্প্যাম চলছে যাদের উপর</div></div>
            </div>
            <div id="activeSpamList" class="active-list"><div class="console-line info">কোনো অ্যাক্টিভ টার্গেট নেই</div></div>
        </div>
        <div class="vip-card">
            <div class="card-header">
                <div class="card-icon"><i class="fas fa-users"></i></div>
                <div><div class="card-title">👥 অনলাইন বট</div><div class="card-subtitle">accs.txt + inv.txt</div></div>
            </div>
            <div id="accountsList" class="accounts-list"><div class="console-line info">লোড হচ্ছে...</div></div>
        </div>
        <div class="vip-card">
            <div class="card-header">
                <div class="card-icon"><i class="fas fa-terminal"></i></div>
                <div><div class="card-title">📟 লাইভ লগ</div><div class="card-subtitle">রিয়েল-টাইম অ্যাক্টিভিটি লগ</div></div>
            </div>
            <div class="console" id="consoleBox">
                <div class="console-line info"><span class="time">[System]</span> 🇮🇳 I AM FIX - IND SERVER LOADED 🇮🇳</div>
                <div class="console-line info"><span class="time">[System]</span> INDIA SERVER | 10 Packets/Bot | 5ms Delay</div>
                <div class="console-line info"><span class="time">[System]</span> NON-STOP SPAM MODE ACTIVE</div>
            </div>
            <div class="status-badge">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="status-dot"></span>
                    <span>STATUS: <span id="statusText">STANDING BY</span></span>
                </div>
                <div style="display: flex; align-items: center; gap: 5px;">
                    <span class="live-dot"></span>
                    <span style="font-size: 0.7rem;">🇮🇳 I AM FIX 🇮🇳</span>
                </div>
            </div>
            <div class="refresh-info"><i class="fas fa-clock"></i> Auto-refresh every 2 seconds | Page never reloads</div>
        </div>
        <div class="footer"><div class="copyright"><i class="fas fa-crown"></i> I AM FIX | IND SERVER ULTIMATE EDITION | 🇮🇳</div></div>
    </div>
    <script>
        const canvas = document.getElementById('matrixCanvas');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&';
        const fontSize = 11;
        const columns = canvas.width / fontSize;
        const drops = Array(Math.floor(columns)).fill(1);
        function drawMatrix() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.03)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#ff9933';
            ctx.font = fontSize + 'px monospace';
            drops.forEach((y, i) => {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, y * fontSize);
                if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
                drops[i]++;
            });
            requestAnimationFrame(drawMatrix);
        }
        drawMatrix();
        window.addEventListener('resize', () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; });
        function logToConsole(message, type = 'info') {
            const consoleBox = document.getElementById('consoleBox');
            const now = new Date();
            const timeStr = now.toLocaleTimeString();
            const line = document.createElement('div');
            line.className = `console-line ${type}`;
            line.innerHTML = `<span class="time">[${timeStr}]</span> ${message}`;
            consoleBox.appendChild(line);
            consoleBox.scrollTop = consoleBox.scrollHeight;
            if (consoleBox.children.length > 100) consoleBox.removeChild(consoleBox.children[0]);
        }
        async function manualRefresh() { logToConsole('🔄 Manual refresh initiated...', 'info'); await refreshStatus(); logToConsole('✅ Status refreshed', 'success'); }
        async function saveAndSpam() {
            const uidsText = document.getElementById('saveUids').value.trim();
            if (!uidsText) { logToConsole('❌ Please enter at least one UID!', 'error'); return; }
            logToConsole('💾 Saving UIDs and starting spam on IND SERVER...', 'attack');
            try {
                const response = await fetch('/api/save-and-spam', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uids: uidsText })
                });
                const data = await response.json();
                if (data.success) { logToConsole(`✅ ${data.message}`, 'success'); document.getElementById('saveUids').value = ''; refreshStatus(); }
                else { logToConsole(`❌ ${data.message}`, 'error'); }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }
        async function startSingleSpam() {
            const uid = document.getElementById('singleUid').value.trim();
            if (!uid) { logToConsole('❌ Please enter target UID!', 'error'); return; }
            if (!/^\\d+$/.test(uid)) { logToConsole('❌ UID must contain only numbers!', 'error'); return; }
            logToConsole(`🎯 Starting spam on IND SERVER for: ${uid}`, 'attack');
            try {
                const response = await fetch('/api/start', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uid: uid })
                });
                const data = await response.json();
                if (data.success) { logToConsole(`✅ ${data.message}`, 'success'); document.getElementById('singleUid').value = ''; refreshStatus(); }
                else { logToConsole(`❌ ${data.message}`, 'error'); }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }
        async function stopSingleSpam() {
            const uid = document.getElementById('singleUid').value.trim();
            if (!uid) { logToConsole('❌ Please enter UID to stop!', 'error'); return; }
            logToConsole(`🛑 Stopping spam on: ${uid}`, 'stop');
            try {
                const response = await fetch('/api/stop', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uid: uid })
                });
                const data = await response.json();
                if (data.success) { logToConsole(`✅ ${data.message}`, 'success'); document.getElementById('singleUid').value = ''; refreshStatus(); }
                else { logToConsole(`❌ ${data.message}`, 'error'); }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }
        async function stopAllSpam() {
            if (!confirm('⚠️ STOP ALL SPAM?')) return;
            logToConsole('🛑 Stopping ALL spam...', 'stop');
            try {
                const response = await fetch('/api/stop-all', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
                const data = await response.json();
                if (data.success) { logToConsole(`✅ ${data.message}`, 'success'); refreshStatus(); }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }
        async function stopFromList(uid) {
            logToConsole(`🛑 Stopping spam on: ${uid}`, 'stop');
            try {
                const response = await fetch('/api/stop', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uid: uid })
                });
                const data = await response.json();
                if (data.success) { logToConsole(`✅ ${data.message}`, 'success'); refreshStatus(); }
            } catch (error) { logToConsole(`❌ Error: ${error.message}`, 'error'); }
        }
        async function refreshStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                if (data.success && data.data) {
                    const status = data.data;
                    document.getElementById('statusText').innerHTML = status.active_count > 0 ? `<i class="fas fa-skull"></i> ATTACKING ${status.active_count} TARGETS` : `<i class="fas fa-check"></i> STANDING BY`;
                    const activeList = document.getElementById('activeSpamList');
                    if (status.active_targets && status.active_targets.length > 0) {
                        activeList.innerHTML = status.active_targets.map(target => `
                            <div class="active-item">
                                <div><span class="active-uid">🎯 ${target.uid}</span><br><span style="font-size:9px; color:#888;">⚡ ${target.elapsed_minutes} min | 🇮🇳 IND SERVER</span></div>
                                <button class="stop-small" onclick="stopFromList('${target.uid}')">STOP</button>
                            </div>
                        `).join('');
                    } else { activeList.innerHTML = '<div class="console-line info">কোনো অ্যাক্টিভ টার্গেট নেই</div>'; }
                    const accountsList = document.getElementById('accountsList');
                    let accountsHtml = '';
                    if (status.room_bots_online && status.room_bots_online.length > 0) {
                        accountsHtml += '<div style="margin-bottom: 5px;"><i class="fas fa-door-open"></i> রুম বট (accs.txt):</div>';
                        status.room_bots_online.forEach(acc => { accountsHtml += `<div class="account-item"><span class="account-type-room">🤖 ${acc}</span> <span style="color:#00ff88;">● অনলাইন</span></div>`; });
                    }
                    if (status.invite_bots_online && status.invite_bots_online.length > 0) {
                        accountsHtml += '<div style="margin: 8px 0 5px;"><i class="fas fa-envelope"></i> ইনভাইট বট (inv.txt):</div>';
                        status.invite_bots_online.forEach(acc => { accountsHtml += `<div class="account-item"><span class="account-type-invite">🤖 ${acc}</span> <span style="color:#00ff88;">● অনলাইন</span></div>`; });
                    }
                    if (status.room_bots_online.length === 0 && status.invite_bots_online.length === 0) { accountsHtml = '<div class="console-line warning">⚠️ কোনো বট অনলাইন নেই</div>'; }
                    accountsList.innerHTML = accountsHtml;
                }
            } catch (error) {}
        }
        setInterval(refreshStatus, 2000);
        refreshStatus();
        document.getElementById('singleUid').addEventListener('keypress', (e) => { if (e.key === 'Enter') startSingleSpam(); });
    </script>
</body>
</html>
'''

# ==================== FF CLIENT ====================
class FF_CLient():
    def __init__(self, id, password, is_inviter=False):
        self.id = id
        self.password = password
        self.is_inviter = is_inviter
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
                    print(f"{G}✅ Online [IND]: {self.id} (Total: {len(connected_clients)}){RS}")
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
                print(f"{G}✅ Registered [IND]: {self.id}{RS}")
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
                print(f"{R}❌ Connection error [IND] {self.id}: {e}{RS}")
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
            print(f'{C}🔐 Login [IND]: {self.id}{RS}')
            return self.ToKen_GeneRaTe(self.Access_ToKen, self.Access_Uid)
        except Exception as e: 
            print(f"{R}❌ Login error [IND] {self.id}: {e}{RS}")
            time.sleep(10)
            return self.Guest_GeneRaTe(uid, password)
                                        
    def GeT_LoGin_PorTs(self, JwT_ToKen, PayLoad, dynamic_url="https://clientbp.ggpolarbear.com"):
        self.UrL = f'{dynamic_url}/GetLoginData'
        self.HeadErs = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JwT_ToKen}',
            'X-Unity-Version': '2022.3.47f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB53',
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
        self.UrL = IND_LOGIN_URL
        self.HeadErs = {
            'X-Unity-Version': '2022.3.47f1',
            'ReleaseVersion': 'OB53',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Host': 'loginbp.ggpolarbear.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'deflate, gzip'
        }   
        
        self.dT = bytes.fromhex('1a13323032352d31312d32362030313a35313a3238220966726565206669726528013a07312e3132332e314232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010e3137362e32382e3133392e313835aa01026172b201203433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014063363961653230386661643732373338623637346232383437623530613361316466613235643161313966616537343566633736616334613065343134633934f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e8039a8002f003af13f80384078004a78f028804b5ee029004a78f029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b205094f70656e474c455332b805ff01c00504e005be7eea05093372645f7061727479f205704b717348543857393347646347335a6f7a454e6646775648746d377171316552554e6149444e67526f626f7a4942744c4f695943633459367a767670634943787a514632734f453463627974774c7334785a62526e70524d706d5752514b6d654f35766373386e51594268777148374bf805e7e4068806019006019a060134a2060134b2062213521146500e590349510e460900115843395f005b510f685b560a6107576d0f0366')
        
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

def start_account(account, is_inviter):
    try:
        type_str = "INVITE" if is_inviter else "ROOM"
        print(f"{G}🚀 Starting {type_str} Bot [IND]: {account['id']}{RS}")
        FF_CLient(account['id'], account['password'], is_inviter=is_inviter)
    except Exception as e:
        print(f"{R}❌ {account['id']} login failed: {e}. Retrying...{RS}")
        time.sleep(5)
        start_account(account, is_inviter)

def run_accounts():
    for account in ROOM_BOTS:
        Thread(target=start_account, args=(account, False), daemon=True).start()
        time.sleep(0.2)
    for account in INVITE_BOTS:
        Thread(target=start_account, args=(account, True), daemon=True).start()
        time.sleep(0.2)

def xMsGFixinG(n):
    return '🗿'.join(str(n)[i:i + 3] for i in range(0, len(str(n)), 3))

def DeCode_PackEt(input_text):
    try:
        from protobuf_decoder.protobuf_decoder import Parser
        parsed_results = Parser().parse(input_text)
        return json.dumps(Fix_PackEt(parsed_results))
    except:
        return None

def Fix_PackEt(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {'wire_type': result.wire_type}
        if result.wire_type in ('varint', 'string', 'bytes'):
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = Fix_PackEt(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

# ==================== MAIN ====================
def main():
    global spam_active
    
    reload_accounts()
    
    print(f"{C}🇮🇳 Logging into IND SERVER bots (accs.txt & inv.txt)...{RS}")
    Thread(target=run_accounts, daemon=True).start()
    
    spam_active = True
    start_spam_engine()
    
    port = int(os.environ.get("PORT", 5000))
    
    print(f"""
    {C}{BOLD}
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                    🇮🇳 I AM FIX - IND SERVER ULTIMATE 🇮🇳                   ║
    ║                                                                           ║
    ║     🌏 REGION       : INDIA SERVER                                       ║
    ║     🔄 ROTATING BOTS: {len(ROOM_BOTS)} Room + {len(INVITE_BOTS)} Invite = {len(ALL_BOTS)} Total          ║
    ║     📦 PACKET CONFIG: 10 Packets/Bot | 5ms Delay                         ║
    ║     ⚡ ROTATION     : After each packet → Next bot immediately           ║
    ║     🔥 NON-STOP     : Continuous flow - NEVER STOPS                      ║
    ║     📝 MESSAGE      : 🇮🇳 I AM FIX 🇮🇳                                     ║
    ║     🌐 WEB PANEL    : http://127.0.0.1:{port}                            ║
    ║     🔗 DIRECT API   : /mahir?uid=12345678                               ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    {RS}
    """)
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
import time
import uuid
import json
import hashlib
import hmac
import requests
from getpass import getpass

# ---------------- CONFIG ----------------
OWNER_USERNAMES = ["owner_username1", "owner_username2"]  # Replace with real usernames
REPLY_DELAY = 2  # seconds
REPLY_TEXT = "OYY MSG MAT KAR"

# Instagram constants
IG_SIG_KEY = b'5ad8d30a9ba6b29f8f67b235c3e60b105d3c8d3ad99c8b5c1b2aefc63e7cddcf'
IG_API_URL = "https://i.instagram.com/api/v1/"
USER_AGENT = "Instagram 321.0.0.27.119 Android (30/11; 480dpi; 1080x2340; Xiaomi; Mi 11; venus; qcom; en_US)"

# HTTP session
session = requests.Session()
session.headers.update({
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "X-IG-App-ID": "936619743392459",
    "X-IG-Capabilities": "3brTvw==",
    "X-IG-Connection-Type": "WIFI",
    "X-IG-Connection-Speed": "-1kbps",
    "X-IG-Bandwidth-Speed-KBPS": "7000.000",
    "X-IG-Bandwidth-TotalBytes-B": "0",
    "X-IG-Bandwidth-TotalTime-MS": "0",
    "X-IG-App-Locale": "en_US",
    "X-IG-Device-Locale": "en_US",
    "X-IG-Mapped-Locale": "en_US",
    "X-FB-HTTP-Engine": "Liger"
})

owner_ids = []

# ---------------- HELPERS ----------------

def generate_device_id():
    return f"android-{uuid.uuid4().hex[:16]}"

def generate_uuid():
    return str(uuid.uuid4())

def generate_signature(data):
    parsed = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
    hmac_hash = hmac.new(IG_SIG_KEY, parsed.encode(), hashlib.sha256).hexdigest()
    return f"ig_sig_key_version=4&signed_body={hmac_hash}.{parsed}"

def resolve_owner_ids():
    for uname in OWNER_USERNAMES:
        try:
            resp = session.get(IG_API_URL + f"users/web_profile_info/?username={uname}")
            if resp.status_code == 200:
                uid = resp.json()["data"]["user"]["id"]
                owner_ids.append(int(uid))
            else:
                print(f"[-] Failed to get user ID for {uname}")
        except Exception as e:
            print(f"[-] Error fetching {uname}:", e)

def get_threads():
    resp = session.get(IG_API_URL + "direct_v2/inbox/")
    if resp.status_code == 200:
        return resp.json().get("inbox", {}).get("threads", [])
    return []

def get_thread_messages(thread_id):
    resp = session.get(IG_API_URL + f"direct_v2/threads/{thread_id}/")
    if resp.status_code == 200:
        return resp.json().get("thread", {}).get("items", [])
    return []

def get_username(user_id):
    resp = session.get(IG_API_URL + f"users/{user_id}/info/")
    if resp.status_code == 200:
        return resp.json()["user"]["username"]
    return "unknown_user"

def send_message(thread_id, text):
    data = {
        "action": "send_item",
        "client_context": str(time.time()).replace('.', ''),
        "text": text,
        "thread_ids": f"[\"{thread_id}\"]"
    }
    resp = session.post(IG_API_URL + "direct_v2/threads/broadcast/text/", data=data)
    return resp.status_code == 200

def monitor_groups(self_id):
    print("[✓] Monitoring group chats...")
    replied_message_ids = {}

    while True:
        threads = get_threads()
        for thread in threads:
            if len(thread.get("users", [])) <= 1:
                continue

            thread_id = thread["thread_id"]
            messages = get_thread_messages(thread_id)
            messages.reverse()

            for msg in messages:
                msg_id = msg.get("item_id")
                sender_id = int(msg.get("user_id"))

                if sender_id in owner_ids or sender_id == self_id:
                    continue

                if msg_id in replied_message_ids.get(thread_id, []):
                    continue

                replied_message_ids.setdefault(thread_id, []).append(msg_id)

                sender_username = get_username(sender_id)
                reply = f"@{sender_username} {REPLY_TEXT}"

                if send_message(thread_id, reply):
                    print(f"[✓] Replied to @{sender_username} in thread {thread_id}")
                else:
                    print(f"[-] Failed to reply to @{sender_username}")
                
                time.sleep(REPLY_DELAY)

        time.sleep(5)

# ---------------- LOGIN WITH CHALLENGE HANDLING ----------------

def handle_challenge(challenge_url, username):
    print("[*] Challenge required.")

    full_url = "https://i.instagram.com" + challenge_url
    resp = session.get(full_url)
    if resp.status_code != 200:
        print("[-] Cannot open challenge URL")
        exit()

    # Choose verification method
    choice = input("[?] Send code to (0 = SMS, 1 = Email): ")
    choice_data = {'choice': choice}
    session.post(full_url, data=choice_data)

    # Enter the security code sent
    code = input("[?] Enter the security code: ").strip()
    verify_data = {
        'security_code': code
    }
    resp = session.post(full_url, data=verify_data)

    if resp.status_code == 200 and "logged_in_user" in resp.text:
        print(f"[+] Challenge resolved! Logged in as {username}")
        return int(resp.json()["logged_in_user"]["pk"])
    else:
        print("[-] Challenge verification failed:", resp.text)
        exit()

def login(username, password):
    device_id = generate_device_id()
    guid = generate_uuid()

    payload = {
        "username": username,
        "enc_password": f"#PWD_INSTAGRAM:0:{int(time.time())}:{password}",
        "guid": guid,
        "device_id": device_id,
        "login_attempt_count": "0"
    }

    sig_data = generate_signature(payload)
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }

    login_url = IG_API_URL + "accounts/login/"
    resp = session.post(login_url, data=sig_data, headers=headers)

    if resp.status_code == 200 and resp.json().get("authenticated"):
        print(f"[+] Logged in as {username}")
        return int(resp.json()["logged_in_user"]["pk"])

    elif "challenge" in resp.text:
        challenge_url = resp.json()["challenge"]["api_path"]
        return handle_challenge(challenge_url, username)
    
    else:
        print("[-] Login failed:", resp.text)
        exit()

# ---------------- START ----------------
if __name__ == "__main__":
    username = input("Enter your Instagram username: ")
    password = getpass("Enter your Instagram password: ")
    self_user_id = login(username, password)
    resolve_owner_ids()
    monitor_groups(self_user_id)

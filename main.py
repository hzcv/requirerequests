import asyncio
from getpass import getpass
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, LoginRequired, BadRequest, ClientError
import traceback
import time

# ---------------- CONFIG ----------------
OWNER_USERNAMES = ["saiyan_hu", "toxiic__devil__18"]
REPLY_TEXT = "Oii msg mt kr vrna teri maa xhod dunga 😂🤣"
REPLY_DELAY = 1  # seconds
RESTART_DELAY = 5  # seconds before restart on crash

cl = Client()
owner_ids = []
replied_message_ids = {}

# ---------------- AUTH ----------------
def ask_credentials():
    username = input("Enter your Instagram username: ")
    password = getpass("Enter your Instagram password: ")
    return username, password

def handle_challenge(username):
    try:
        cl.challenge_resolve(auto=True)
        code = input("[?] Enter the security code sent to your email: ").strip()
        cl.challenge_send_security_code(code)
    except Exception as e:
        print("[-] Failed to resolve challenge:", e)

def login_flow():
    username, password = ask_credentials()
    try:
        cl.login(username, password)
    except ChallengeRequired:
        print("[!] Challenge required. Trying to resolve.")
        handle_challenge(username)
    except (LoginRequired, BadRequest, ClientError) as e:
        print("[!] Instagram flagged automated behavior. Skipping and continuing.")
    except Exception as e:
        print("[-] Login failed:", e)
        exit()

    print(f"[+] Logged in as {username}")
    return cl.user_id_from_username(username)

def resolve_owner_ids():
    for uname in OWNER_USERNAMES:
        try:
            uid = cl.user_id_from_username(uname)
            owner_ids.append(uid)
        except:
            print(f"[-] Failed to get user ID for owner '{uname}'")

# ---------------- ASYNC HANDLER ----------------
async def reply_to_message(thread_id, msg, self_id):
    if msg.user_id in owner_ids or msg.user_id == self_id:
        return

    if msg.id in replied_message_ids.get(thread_id, []):
        return

    replied_message_ids.setdefault(thread_id, []).append(msg.id)

    try:
        sender_username = await asyncio.to_thread(cl.user_info, msg.user_id).username
        reply = f"@{sender_username} {REPLY_TEXT}"
        await asyncio.to_thread(cl.direct_send, reply, thread_ids=[thread_id])
        print(f"[✓] Replied to @{sender_username} in thread {thread_id}")
        await asyncio.sleep(REPLY_DELAY)
    except (LoginRequired, BadRequest, ClientError) as e:
        print(f"[!] Skipping blocked reply due to Instagram automation detection.")
    except Exception as e:
        print(f"[!] General error replying to user ID {msg.user_id}: {e}")

async def monitor_groups(self_id):
    print("[✓] Monitoring group chats with asyncio...")
    while True:
        try:
            threads = await asyncio.to_thread(cl.direct_threads)
            for thread in threads:
                if len(thread.users) <= 1:
                    continue  # Not a group chat

                thread_id = thread.id
                messages = await asyncio.to_thread(cl.direct_messages, thread_id, 10)
                messages.reverse()

                for msg in messages:
                    await reply_to_message(thread_id, msg, self_id)

            await asyncio.sleep(0.5)
        except (LoginRequired, BadRequest, ClientError) as e:
            print("[!] Skipping thread check due to automation detection.")
            await asyncio.sleep(RESTART_DELAY)
        except Exception as e:
            print("[!] Unexpected error in monitor loop:", e)
            traceback.print_exc()
            await asyncio.sleep(RESTART_DELAY)

# ---------------- RESTART WRAPPER ----------------
def main_loop():
    while True:
        try:
            self_user_id = login_flow()
            resolve_owner_ids()
            asyncio.run(monitor_groups(self_user_id))
        except Exception as e:
            print("\n[!] Bot crashed! Restarting in 5 seconds...")
            traceback.print_exc()
            time.sleep(RESTART_DELAY)

# ---------------- START ----------------
if __name__ == "__main__":
    main_loop()

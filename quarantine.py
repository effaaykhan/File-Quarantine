#!/usr/bin/env python3
import sys, os, json, time, hashlib, shutil, datetime

ADD = 0
DELETE = 1
COOLDOWN_SECONDS = 300  # 5 min cooldown to avoid looping

STATE_FILE = r"C:\RTGS_quarantine\quarantine_state.json"

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            import json
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_state(state):
    import json
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

if __name__ == "__main__":
    data = json.loads(sys.stdin.readline())
    cmd = data.get("command")
    syscheck = data["parameters"]["alert"]["syscheck"]
    path = syscheck["path"]

    if cmd == "add":
        qs = r"C:\RTGS_quarantine"
        os.makedirs(qs, exist_ok=True)

        state = load_state()
        now = time.time()

        # Check cooldown
        if path in state and now - state[path] < COOLDOWN_SECONDS:
            sys.exit(0)  # Skip quarantine if recently quarantined

        h1 = hashlib.sha256(open(path, "rb").read()).hexdigest()
        basename = os.path.basename(path)
        dest = os.path.join(qs, f"{basename}.quarantine.{int(time.time())}")

        try:
            shutil.move(path, dest)
        except Exception as e:
            with open(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log", "a") as log:
                log.write(f"{datetime.datetime.now()}: DEFAIL {e}\n")
            sys.exit(1)

        # Record quarantine time
        state[path] = now
        save_state(state)

        control = json.dumps({
            "version": 1,
            "origin": {"name": "quarantine_rtgs", "module": "active-response"},
            "command": "check_keys",
            "parameters": {"keys": [dest]}
        })
        print(control)
        sys.stdout.flush()

        resp = json.loads(sys.stdin.readline())
        if resp.get("command") == "continue":
            with open(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log", "a") as log:
                log.write(f"{datetime.datetime.now()}: quarantined {path}\n")

            time.sleep(120)  # Wait for 2 mins

            newh = hashlib.sha256(open(dest, "rb").read()).hexdigest()
            if newh == h1:
                shutil.move(dest, path)
                with open(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log", "a") as log:
                    log.write(f"{datetime.datetime.now()}: restored {path}\n")

        sys.exit(0)

    elif cmd == "delete":
        sys.exit(0)

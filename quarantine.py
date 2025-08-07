#!/usr/bin/env python3
import sys, os, json, time, hashlib, shutil, datetime
ADD=0; DELETE=1
if __name__=="__main__":
    data = json.loads(sys.stdin.readline())
    cmd = data.get("command")
    syscheck = data["parameters"]["alert"]["syscheck"]
    path = syscheck["path"]
    if cmd == "add":
        qs = r"C:\wazuh-quarantine"
        os.makedirs(qs, exist_ok=True)
        h1 = hashlib.sha256(open(path, "rb").read()).hexdigest()
        basename = os.path.basename(path)
        dest = os.path.join(qs, f"{basename}.quarantine.{int(time.time())}")
        try:
            shutil.move(path, dest)
        except Exception as e:
            open(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log", "a").write(f"{datetime.datetime.now()}: DEFAIL {e}\n")
            sys.exit(1)
        # signal to manager: we are running, return ADD so a delete will come after timeout
        control = json.dumps({"version":1,"origin":{"name":"quarantine_rtgs","module":"active-response"},"command":"check_keys","parameters":{"keys":[dest]}})
        print(control); sys.stdout.flush()
        resp = json.loads(sys.stdin.readline())
        if resp.get("command")=="continue":
            open(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log", "a").write(f"{datetime.datetime.now()}: quarantined {path}\n")
            time.sleep(900)  # wait 15 mins
            newh = hashlib.sha256(open(dest, "rb").read()).hexdigest()
            if newh == h1:
                shutil.move(dest, path)
                open(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log", "a").write(f"{datetime.datetime.now()}: restored {path}\n")
        sys.exit(0)
    elif cmd == "delete":
        sys.exit(0)

import unittest
from pathlib import Path
from stynpilot import local_ai_readiness as ready

class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.uid = 1000
        self.cg = "/user.slice/user-1000.slice/user@1000.service/app.slice/" + ready.UNIT
        self.info = f"ActiveState=active\nMainPID=123\nControlGroup={self.cg}\nKillMode=control-group\n"
        self.listener = 'LISTEN 0 4096 127.0.0.1:11435 0.0.0.0:* users:(("ollama",pid=123,fd=3))'
        self.data = {
            "/proc/123/comm": b"ollama\n", "/proc/123/status": b"Uid:\t1000\t1000\t1000\t1000\n",
            "/proc/123/cgroup": ("0::"+self.cg+"\n").encode(),
            "/proc/123/environ": b"\0".join(k+b"="+v for k,v in ready.ENV_REQUIRED.items()) + b"\0PRIVATE=synthetic-secret\0",
        }
        for key,value in {"memory.high":str(7*ready.GIB),"memory.max":str(9*ready.GIB),
                          "memory.swap.max":"0","pids.max":"128","cpu.max":"400000 100000",
                          "memory.current":"123456"}.items():
            self.data["/sys/fs/cgroup"+self.cg+"/"+key]=value.encode()
    def run_cmd(self, argv):
        if argv == ready.SHOW: return self.info
        if argv == ready.LISTEN: return self.listener
        self.fail("unexpected command")
    def read(self,path,limit=65536):
        value=self.data[str(path)]
        if len(value)>limit: raise ValueError("oversize")
        return value
    def report(self):
        return ready.inspect(run=self.run_cmd,read=self.read,uid=self.uid)
    def test_ready_and_private_environment(self):
        r=self.report()
        self.assertTrue(r["resource_checks_passed"],r)
        self.assertNotIn("synthetic-secret",repr(r))
    def test_missing_or_unbounded_limits(self):
        for key,value in (("memory.max",b"max"),("memory.high",b"max"),
                          ("cpu.max",b"max 100000"),("pids.max",b"max"),
                          ("memory.swap.max",b"1"),("memory.max",b"99999999999"),
                          ("cpu.max",b"600000 100000")):
            path="/sys/fs/cgroup"+self.cg+"/"+key
            original=self.data[path]
            self.data[path]=value
            self.assertFalse(self.report()["resource_checks_passed"],key)
            self.data[path]=original
    def test_wrong_identity_or_cgroup(self):
        self.data["/proc/123/cgroup"]=b"0::/unrelated"
        self.assertFalse(self.report()["resource_checks_passed"])
        self.data["/proc/123/cgroup"]=("0::"+self.cg).encode()
        self.data["/proc/123/status"]=b"Uid: 0 0 0 0"
        self.assertFalse(self.report()["resource_checks_passed"])
    def test_listener_scope_and_identity(self):
        old=self.listener
        for s in (old.replace("127.0.0.1:","0.0.0.0:"),old.replace("pid=123","pid=456"),old+"\n"+old,""):
            self.listener=s
            self.assertFalse(self.report()["resource_checks_passed"])
    def test_environment_required_and_duplicate_refused(self):
        old=self.data["/proc/123/environ"]
        for s in (old.replace(b"OLLAMA_NO_CLOUD=1",b"OLLAMA_NO_CLOUD=0"),
                  old+b"OLLAMA_HOST=127.0.0.1:11435\0",b""):
            self.data["/proc/123/environ"]=s
            self.assertFalse(self.report()["resource_checks_passed"])
    def test_missing_evidence_or_restart(self):
        old=self.info
        self.info=old.replace("ActiveState=active","ActiveState=inactive")
        self.assertFalse(self.report()["resource_checks_passed"])
        self.info=old
        calls=[]
        def run(argv):
            if argv == ready.SHOW:
                calls.append(1)
                return old if len(calls)==1 else old.replace("123","124")
            return self.listener
        self.assertFalse(ready.inspect(run=run,read=self.read,uid=self.uid)["resource_checks_passed"])
        del self.data["/proc/123/comm"]
        self.assertFalse(self.report()["resource_checks_passed"])

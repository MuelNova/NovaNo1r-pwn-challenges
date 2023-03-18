import os
os.chmod('/tmp/x', 0o777)
os.execve('/tmp/x',['x'],{})
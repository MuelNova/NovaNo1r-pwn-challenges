from pwn import *
#context.update(log_level='debug')

HOST = "10.112.100.47"
PORT = 1717
USER = "pwn"
PW = "pwn"

filename = "exp.c"
output_name = 'fs/main'
run_file = './start.sh'
compile_arg = '-static'

chunk_size = 0x200

def compile():
    log.info("Compile...")
    os.system(f"gcc {compile_arg} {filename} -o {output_name}".encode())

def exec_cmd(cmd: bytes):
    r.sendline(cmd)
    r.recvuntil(b"$ ")

def upload():
    p = log.progress("Uploading...")

    with open(output_name, "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data)

    r.recvuntil(b"$ ")

    for i in range(0, len(encoded), chunk_size):
        p.status("%d / %d" % (i, len(encoded)))
        exec_cmd(b"echo \"%s\" >> benc" % (encoded[i:i+chunk_size]))

    exec_cmd(b"cat benc | base64 -d > bout")
    exec_cmd(b"chmod +x bout")

    p.success()

def exploit(r):
#    compile()
    upload()

    r.interactive()

    return

if __name__ == "__main__":
    if len(sys.argv) > 1:
        session = ssh(USER, HOST, PORT, PW)
        r = session.run("/bin/sh")
        exploit(r)
    else:
        r = process(["bash", run_file])
        print(util.proc.pidof(r))
        pause(3)
        exploit(r)

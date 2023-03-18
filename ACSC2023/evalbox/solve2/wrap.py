import sys

with open('main', 'rb') as f:
    data = f.read()

with open(sys.argv[1], "rb") as f:
    c = f.read()
    c = c.replace(b'PLACEHOLDER', data.hex().encode())
    # print(c.decode())
    h = c.hex()
    print(f'exec(bytes.fromhex("{h}"))')
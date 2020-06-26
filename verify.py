import ecdsa, sys	
from hashlib import sha256

if len(sys.argv) != 4:
	print(sys.argv[0], "[pubkey] [quote file] [sig file]")
	exit(1)

with open(sys.argv[2],"rb") as f:
	message = f.read()
with open(sys.argv[3],"rb") as f:
	file = f.read()
	sig =  file[6:38] + file[40:]
public_key = bytes.fromhex(sys.argv[1])

vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.NIST256p, hashfunc=sha256)

vk.verify(sig, message)
print("signature ok")

import hashlib

file = "./test.txt" # Location of the file (can be set a different way)
BLOCK_SIZE = 65536 # The size of each read from the file

file_hash = hashlib.sha256() # Create the hash object, can use something other than `.sha256()` if you wish
with open(file, 'rb') as f: # Open the file to read it's bytes
    fb = f.read(BLOCK_SIZE) # Read from the file. Take in the amount declared above
    while len(fb) > 0: # While there is still data being read from the file
        file_hash.update(fb) # Update the hash
        fb = f.read(BLOCK_SIZE) # Read the next block from the file

print (file_hash.hexdigest()) # Get the hexadecimal digest of the hash
print(len(file_hash.hexdigest()))

x = b'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
y = bytes(file_hash.hexdigest(), 'utf-8')
print(x+y)
z = x[-64:]
print(z)
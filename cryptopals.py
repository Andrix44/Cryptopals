#!/bin/python3
from base64 import b64decode, b64encode
import string
from Crypto.Cipher import AES

def HexToBase64(hexstring):
    return b64encode(bytes.fromhex(hexstring))

def FixedXOR(hexstring, key):
    val = int(hexstring, 16)
    key = int(key, 16)
    return hex(val ^ key)[2:]

def SingleByteXOR(bytes_in, key):
    if (isinstance(bytes_in, str)):
        bytes_in = bytes.fromhex(bytes_in)
    res = []
    for byte in bytes_in:
        res.append(byte ^ key)
    res = ''.join([chr(x) for x in res])
    return res

def CheckValidString(s, precision):
    return all([(ch in string.printable) for ch in s]) and [(ch in string.punctuation) for ch in s].count(True) < (len(s) / precision)

def CrackSingleByteXOR(bytes_in):
    ret = ""
    for i in range(1, 0x100):
        ret = SingleByteXOR(bytes_in, i)
        if(CheckValidString(ret, 8)):
            return {"orig": bytes_in, "cracked": ret, "key": i}
            #print({"orig": bytes_in, "cracked": ret, "key": i})
    return 0

def MultiByteXOR(bytes_in, key):
    if (isinstance(bytes_in, str)):
        bytes_in = bytes(bytes_in, "utf-8")
    key_dec = [ord(x) for x in key]
    res = []
    for i, byte in enumerate(bytes_in):
        res.append(byte ^ key_dec[i % len(key)])
    res = ''.join([hex(x)[2:].rjust(2, "0") for x in res])
    return res

def HammingDist(str1, str2):
    str1b = ''.join("{0:08b}".format(x, 'b') for x in str1)
    str2b = ''.join("{0:08b}".format(x, 'b') for x in str2)
    return sum(char1 != char2 for char1, char2 in zip(str1b, str2b))
    #return len(list(filter(lambda x : ord(x[0]) ^ ord(x[1]), zip(str1b, str2b))))

def CrackMultiByteXOR(data_enc):
    distances = {}
    distance_avg_list = []
    max_key_len = min(len(data_enc) // 4, 41)
    for keysize in range(2, max_key_len):
        distance_avg_list = []
        for i in range(0, len(data_enc) // (keysize * 2), 2):
            data1 = data_enc[(i+0)*keysize:(i+1)*keysize]
            data2 = data_enc[(i+1)*keysize:(i+2)*keysize]
            distance = HammingDist(data1, data2) / keysize
            distance_avg_list.append(distance)
        distance_avg = sum(distance_avg_list) / len(distance_avg_list)
        #print(str(keysize) + ": " + str(distance_avg))
        distances[str(keysize)] = distance_avg

    found_key = ""
    best_keys = [int(i) for i in list(dict(sorted(distances.items(), key = lambda kv: kv[1])))[:1]] # Increase the number of keys if neccesary
    #print("Found best key sizes: " + str(best_keys))
    for x in range(len(best_keys)):
        keysize = best_keys[x]
        blocks = [data_enc[i: i + keysize] for i in range(0, len(data_enc), keysize)]
        #print(blocks)
        # Last block might be shorter than the key
        if(len(blocks[-1]) < keysize): blocks.pop(-1)
        transposed = [b''] * keysize
        for i in range(keysize):
            for block in blocks:
                transposed[i] += bytes([block[i]])
        #print(transposed)
        for block in transposed:
            found_key += chr(CrackSingleByteXOR(block)["key"])

    return found_key

def HasRepeatedBlocks(bytes_in):
    assert(len(bytes_in) % 16 == 0), "Data length must be a multiple of block length"
    num_blocks = len(bytes_in) // 16
    blocks = [bytes_in[(i+0)*16: (i+1)*16] for i in range(num_blocks)]
    return (len(set(blocks)) != num_blocks)

def Tests():
    val = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    res = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert(HexToBase64(val) == res)

    val = "1c0111001f010100061a024b53535009181c"
    key = "686974207468652062756c6c277320657965"
    res = "746865206b696420646f6e277420706c6179"
    assert(FixedXOR(val, key) == res)

    val = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key = 0x58
    res = "Cooking MC's like a pound of bacon"
    #print(CrackSingleByteXOR(val))
    assert(SingleByteXOR(val, key) == res)

    try:
        val = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
        key = 0x35
        res = "Now that the party is jumping\n"
        with open("4.txt", 'r') as f:
            line = "dummy_val"
            while(line != ""):
                line = f.readline()
                returned = CrackSingleByteXOR(line)
                if(returned):
                    print(returned)
        assert(SingleByteXOR(val, key) == res)
    except FileNotFoundError:
        print("File 4.txt not found!")

    val = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    res = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    key = "ICE"
    assert(MultiByteXOR(val, key) == res)

    str1 = b"this is a test"
    str2 = b"wokka wokka!!!"
    assert(HammingDist(str1, str2) == 37)

    try:
        with open("6.txt", 'r') as f:
            data_enc = b64decode(f.read().strip())
        assert(CrackMultiByteXOR(data_enc) == "Terminator X: Bring the noise")
        #print(bytes.fromhex(MultiByteXOR(data_enc, "Terminator X: Bring the noise")).decode("utf-8"))
    except FileNotFoundError:
        print("File 6.txt not found!")

    try:
        with open("7.txt", 'r') as f:
            data_enc = b64decode(f.read().strip())
        key = b"YELLOW SUBMARINE"
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(data_enc).decode("utf-8")
        assert(plaintext.startswith("I'm back and I'm ringin' the bell"))
        #print(plaintext)
    except FileNotFoundError:
        print("File 7.txt not found!")

    try:
        with open("8.txt", 'r') as f:
            lines = [bytes.fromhex(line.strip()) for line in f.readlines()]
        for line in lines:
            if(HasRepeatedBlocks(line)):
                res = line
        assert(res.hex().startswith("d8806197"))
    except FileNotFoundError:
        print("File 8.txt not found!")

if(__name__ == "__main__"):
    Tests()

    exit()
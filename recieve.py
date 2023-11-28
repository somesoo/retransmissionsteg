import scapy.all
import json

with open('vars.json', 'r') as f:
    code = json.load(f)
o = code['O']
d = code['D']
i = code['I']
j = code['J']
print(o, d, i, j)

stegand_cap = scapy.all.rdpcap('stegand.pcap')
stegand_packets = [pac for pac in stegand_cap if pac.haslayer(scapy.all.TCP)]
steg = [pac for pac in stegand_packets if pac.haslayer(scapy.all.Ether) and pac.dst.lower() == "ac:19:8e:c7:60:a0"]
#print(len(steg))
steg.sort()

seqNrs = []
seqAll = []
seqRet = []
for packet in steg:
    seqAll.append(packet.seq)
    if packet.seq not in seqNrs:
        seqNrs.append(packet.seq)
    elif packet.seq not in seqRet:
        seqRet.append(packet.seq)

#print(len(seqNrs))
#print(len(seqRet))
seqNrs.sort()

binary_rep = []
#print(seqNrs[1*d+o])
if seqNrs[1*d+o] in seqRet:
    print(1)
for u in range(len(seqNrs) // d-1):
    x = 0
    if seqNrs[u*d+o] in seqRet:
        x += 1
    if seqNrs[u*d+o+i] in seqRet:
        x += 1
    if seqNrs[u*d+o+i+j] in seqRet:
        x += 1
    if x == 3:
        binary_rep.append('1')
    else:
        binary_rep.append('0')
           
def decode(binary_representation):
    decode_hidden_message = lambda binary_str: ''.join(chr(int(''.join(binary_str[i:i+8]), 2)) for i in range(0, len(binary_str), 8))
    decoded_rep = decode_hidden_message(binary_representation)
    return decoded_rep
print(binary_rep)
print(decode(binary_rep))
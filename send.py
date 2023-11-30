import scapy.all
from collections import Counter
from random import randint
import json

## Step 1
hidden_message = "troche dluzsza wiadomosc, da rade"
encode_hidden_message = lambda x: [z for y in x for z in f'{ord(y):08b}' ]
binary_representation = encode_hidden_message(hidden_message)
print(binary_representation)

## Step 2
scapy_cap = scapy.all.rdpcap('download_deb.pcap')
htc_packets = [pac for pac in scapy_cap if pac.haslayer(scapy.all.TCP)]
inbound = [pac for pac in htc_packets if pac.haslayer(scapy.all.Ether) and pac.dst.lower() == "52:82:48:7f:ca:84"]
# ac:19:8e:c7:60:a0
#print(len(inbound))

inbound.sort()
seq_all = []
seqNrs = []
seq2= []
for packet in inbound:
    seq_all.append(packet.seq)
    if packet.seq not in seqNrs:
        seqNrs.append(packet.seq)

seqNrs.sort()
#print(len(seqNrs))  
print(len(seqNrs))
D = randint(20, len(seqNrs) // (len(binary_representation)+1))
O = randint(1, D)
I = randint(2, D)
J = randint(1, D-I)
varsy = { 
    "D":D,
    "O":O,
    "I":I,
    "J":J
    }

jsonobject = json.dumps(varsy)
with open('vars.json', 'w') as file:
    file.write(jsonobject)
#print(jsonobject)
# Step 3 -> check if we need to sen 1 or 0, if 1 add seq numbers to the list.

retransmited = []
for i in range(len(binary_representation)):
    if binary_representation[i] == '1':
        retransmited.append(seqNrs[O+D*i])
        retransmited.append(seqNrs[O+D*i+I])
        retransmited.append(seqNrs[O+D*i+I+J])

#print(len(retransmited))
#print(retransmited[0])


if all(count == 1 for count in Counter(retransmited).values()):
    print("List contains all unique elements")
else:
    print("List contains does not contains all unique elements")


outbound = []
for i in inbound:
    outbound.append(i)
    if i.seq in retransmited:
        outbound.append(i)

print(len(outbound))
#print(len(inbound))

def write(pkt):
    scapy.all.wrpcap('stegand.pcap', pkt, append=True)  #appends packet to output file

write(outbound)


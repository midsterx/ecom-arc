from netfilterqueue import NetfilterQueue
import os

# _NFQ_INIT = 'iptables -I INPUT -j NFQUEUE --queue-num %d'
# _NFQ_CLOSE = 'iptables -D INPUT -j NFQUEUE --queue-num %d'

_NFQ_INIT = 'iptables -I OUTPUT -d 192.168.75.97 -j NFQUEUE --queue-num %d'
_NFQ_CLOSE = 'iptables -D OUTPUT -d 192.168.75.97 -j NFQUEUE --queue-num %d'


def print_and_accept(pkt):
    print(pkt)
    pkt.accept()

inputipaddr =  "202.137.235.12"
qnum = 1
setup = _NFQ_INIT % qnum
os.system(setup)
print("Setting up IPTables: " + setup)
print("Initializing NetfilterQueue...")
nfq = NetfilterQueue()
print("Binding...")
nfq.bind(qnum, print_and_accept)

try:
    nfq.run()
    print("Running")
except KeyboardInterrupt:
    print("Interrupted")

print ("Unbinding...")
nfq.unbind()
teardown = _NFQ_CLOSE % qnum
os.system(teardown)
print('\nTore down IPTables: ' + teardown)
print ("Quitting Firewall")
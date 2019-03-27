1. Always run the code in sudo mode
2. To set the packets to go to NFQUEUE:
	sudo iptables -I OUTPUT -d 173.16.0.229 -j NFQUEUE --queue-num 1
3. To reset to normal:
	sudo iptables -I OUTPUT -d 173.16.0.229 -j ACCEPT

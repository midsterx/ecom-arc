from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime

try:
	target = input("[*] Enter Target IP Address: ")
	min_port = input("[*] Enter Minimum Port Number: ")
	max_port = input("[*] Enter Maximum Port Number: ")
	try: 
		

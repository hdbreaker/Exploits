from capstone import *

for i in range(1,256):
	opcodes = chr(i)+"\x48\x8B\x01\xC3\xC3\xC3\xC3"
	print "[#] case %s" % hex(i)
	print "############"
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	for i in md.disasm(opcodes, 0x00):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
	print "############"
	print ""

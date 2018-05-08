#!/usr/bin/python
# MIT License
#
# Copyright (c) 2018 Hashim Jawad
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import os
import time
import struct
import re
import binascii

# colors (*NIX systems only)
W = '\033[0m'  # white
R = '\033[31m' # red
G = '\033[32m' # green
O = '\033[33m' # orange

# make sure pefile library is installed
try:
	import pefile
except:
	print "["+R+"!"+W+"] Please install pefile and run the program. Use the following command to install pefile:"
	print "    "+O+"pip install pefile"+W
	sys.exit(0)

# make sure pydasm library is installed
try:
	import pydasm
except:
	print "["+R+"!"+W+"] Please install pydasm and run the program. Use the following command if you're running Kali Linux:"
	print "    "+O+"wget 'https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/libdasm/libdasm-beta.zip' -O libdasm-beta.zip"+W
	print "    "+O+"unzip libdasm-beta.zip"+W
	print "    "+O+"sudo apt-get install python2.7-dev"+W
	print "    "+O+"sudo make"+W
	print "    "+O+"cd pydasm"+W
	print "    "+O+"sudo python setup.py install"+W
	sys.exit(0)

# make sure SectionDoubleP.py is within the same directory of SubRosa.py
try:
	from SectionDoubleP import *
except:
	print "["+R+"!"+W+"] Please make sure SectionDoubleP.py is within the same directory as SubRosa.py. Use the following to download:"
	print "    "+O+"git clone git://git.n0p.cc/SectionDoubleP.git"+W
	sys.exit(0)

global IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x40



# Search PE file for potential code cave
def FindCodeCave(pe, Size):

	for section in pe.sections:
		SectionName           = section.Name
		SectionVirtualAddress = section.VirtualAddress 
		SectionCodeCave       = ""
		VirtualOffset         = 0
		RawOffset             = 0
		NullByteCount         = 0
		ByteCount             = 0
		SectionHeader         = section
		SectionStart          = SectionHeader.VirtualAddress
		SectionStop           = SectionStart+SectionHeader.SizeOfRawData
		data                  = binascii.hexlify(pe.get_memory_mapped_image()[SectionStart:SectionStop])
		SectionData           = re.findall(r'.{1,2}',data,re.DOTALL)

		for byte in SectionData:
			if byte == "00":
				NullByteCount += 1
				if NullByteCount >= Size:
					RawOffset = ByteCount - NullByteCount + 2
					VirtualOffset = struct.pack("L",(RawOffset) + SectionVirtualAddress - pe.OPTIONAL_HEADER.AddressOfEntryPoint)
					SectionCodeCave = SectionName
					print "["+G+"+"+W+"] Found %i+ in %s section" %(NullByteCount, SectionCodeCave)
					print "    "+O+"*"+W+" Section Name  : " +O+ section.Name +W
					print "    "+O+"*"+W+" Virtual Offset: " +O+ "0x" + binascii.hexlify(VirtualOffset) +W
					print "    "+O+"*"+W+" Raw Offset    : " +O+ "0x%i" %(int(RawOffset)) +W	
					print "["+G+"+"+W+"] Making sure the section has read/write/execute permissions.."
					time.sleep(1) 
					try:
						section.Characteristics = 0xE0000040
					except:
						print "["+R+"!"+W+"] Failed making the section writeable, please do it manually"
					return pe
			else:
				NullByteCount = 0
			ByteCount +=1
	print "["+R+"!"+W+"] PE file conatin no %i+ bytes Code Caves" %(int(Size))

# Add new section to PE file, <3 n0p git://git.n0p.cc/SectionDoubleP.git
def AddSection(pe, NewSectionSize):

	NewSectionVirtualOffset = 0
	if NewSectionVirtualOffset == 0:
		sections = SectionDoubleP(pe)
		NewSection = ".Evil"
		print "["+G+"+"+W+"] Making sure the section has read/write/execute permissions.."
		time.sleep(1)
		try:
			for section in pe.sections:
				if NewSection.strip().lower() in section.Name.strip().lower():
					section.Characteristics = 0xE0000040
		except:
			print "["+R+"!"+W+"] Failed making the section writeable, please do it manually"

		pe = sections.push_back(NewSection, VirtualSize=NewSectionSize, RawSize=NewSectionSize)

		for section in pe.sections:
			if NewSection.strip().lower() in section.Name.strip().lower():
				try:				
					NewSectionHeader         = section
					NewSectionVirtualAddress = NewSectionHeader.VirtualAddress
					NewSectionVirtualOffset  = struct.pack("L", NewSectionVirtualAddress - pe.OPTIONAL_HEADER.AddressOfEntryPoint)
					NewSectionRawOffset      = 0
					NewSectionAddress = hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint + struct.unpack("L", NewSectionVirtualOffset)[0])
					print "["+G+"+"+W+"] New section '"+O+NewSection+W+"' is located at " + NewSectionAddress
					return pe
				except:
					"["+R+"!"+W+"] Could not fetch header information. Please check new section permissions"
	
# Check ASLR
def CheckASLR(pe):

	# <3 https://github.com/0vercl0k/stuffz/blob/master/remove_aslr_bin.py
	if (pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE):
		print "["+R+"!"+W+"] ASLR is enabled"
		answer = None
		while answer not in ("yes", "no", "y", "n"):
			answer = raw_input("["+G+"+"+W+"] Would you like to disable ASLR? Enter Yes or No: ").lower()
			if answer == "yes" or answer == "y":
				print "["+G+"+"+W+"] Disabling ASLR.."
				time.sleep(1)
				pe.OPTIONAL_HEADER.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
			elif answer == "no" or answer == "n":
				pass
			else:
				print "Please enter Yes or No."
	else:
		print "["+G+"+"+W+"] ASLR is disabled"
		pass
	return pe

# Save changes to PE file if there is any		
def SaveChanges(pe, file):

	try:
		FileName = "Modified_" + file 
		pe.write(filename=FileName)
		print "["+G+"+"+W+"] Modified PE file has been saved as: " + FileName
	except:
		print "["+R+"!"+W+"] Modified PE file cannot be saved"

# Split file to chuncks		
def SplitPEFile(file, ChunckSize, StartOffset):

	PEFileSize    = os.path.getsize(file)
	f             = open(file, "rb")
	FileName      = os.path.splitext(file)[0]
	FileExtension = os.path.splitext(file)[1]
	Byte          = ""

	if StartOffset > 0:
		Byte  = f.read(StartOffset)
	Pointer       = f.tell()

	while Pointer < PEFileSize:
		Byte += f.read(ChunckSize)
		ChunckFileName = FileName + "_" + str(len(Byte)) + FileExtension
		Pointer = f.tell()
		print "    "+O+"*"+W+" Chunck File : " +O+ ChunckFileName +W+ "    | Size: " +O+ str(len(Byte)) +W
		NewFileHeader = open(ChunckFileName, "wb")
		NewFileHeader.write(Byte)
		NewFileHeader.close()
	f.close()

def main():

	if len(sys.argv) < 2:
		print "Usage: python SubRosa.py <"+G+"filename"+W+">"
		sys.exit(0)
	
	file = sys.argv[1]
	answer = None
	
	try:
		print "["+G+"+"+W+"] Opening PE File '" +O+file+W+ "'.."
		pe = pefile.PE(file)
	except:
		print "["+R+"!"+W+"] File %s '" +O+file+W+ "' cannot be opened"
		sys.exit(0)
	
	print "["+G+"+"+W+"] Checking ASLR settings.."
	time.sleep(1)
	CheckASLR(pe)

	# split PE file logic
	answer = None
	while answer not in ("yes", "no", "y", "n"):
		answer = raw_input("["+G+"+"+W+"] Would you like to split PE file? Enter Yes or No: ").lower()
		if answer == "yes" or answer == "y":
			ChunckSize = raw_input("["+G+"+"+W+"] Please enter chunck size (default is 1000): ").lower()
			if not ChunckSize:
				ChunckSize  = 1000
				StartOffset = raw_input("["+G+"+"+W+"] Please specify start offset (default is 0): ").lower()
				if not StartOffset:
					StartOffset = 0
					print "["+G+"+"+W+"] Splitting PE file to %i+ byte chuncks.." %(ChunckSize)
					time.sleep(1)
					SplitPEFile(file, ChunckSize, StartOffset)
				else:
					StartOffset = int(StartOffset)
					print "["+G+"+"+W+"] Splitting PE file to %i+ byte chuncks.." %(ChunckSize)
					time.sleep(1)
					SplitPEFile(file, ChunckSize, StartOffset)
					
			else:
				ChunckSize = int(ChunckSize)
				StartOffset = raw_input("["+G+"+"+W+"] Please specify start offset (default is 0): ").lower()
				if not StartOffset:
					StartOffset = 0
					print "["+G+"+"+W+"] Splitting PE file to %i+ byte chuncks.." %(ChunckSize)
					time.sleep(1)
					SplitPEFile(file, ChunckSize, StartOffset)
				else:
					StartOffset = int(StartOffset)
					print "["+G+"+"+W+"] Splitting PE file to %i+ byte chuncks.." %(ChunckSize)
					time.sleep(1)
					SplitPEFile(file, ChunckSize, StartOffset)
		elif answer == "no" or answer == "n":
			pass
		else:
			print "Please enter Yes or No."

	print "["+G+"+"+W+"] Preparing PE file for code cave search.."
	time.sleep(1)
	
	# code cave search logic
	answer = None
	while answer not in ("yes", "no", "y", "n"):
		answer = raw_input("["+G+"+"+W+"] Would you like to search for code caves? Enter Yes or No: ").lower()
		if answer == "yes" or answer == "y":
			Size = raw_input("["+G+"+"+W+"] Please enter code cave size (default is 1000): ").lower()
			if not Size:
				Size = 1000
				print "["+G+"+"+W+"] Looking for %i+ bytes code caves.." %(Size)
				time.sleep(1)
				FindCodeCave(pe, Size)
			else:	
				Size = int(Size)
				print "["+G+"+"+W+"] Looking for %i+ bytes code caves.." %(Size)
				time.sleep(1)
				FindCodeCave(pe, Size)				
		elif answer == "no" or answer == "n":
			pass
		else:
			print "Please enter Yes or No."

	# add new section logic
	answer = None
	while answer not in ("yes", "no", "y", "n"):
		answer = raw_input("["+G+"+"+W+"] Would you like to add new section in PE file? Enter Yes or No: ").lower()
		if answer == "yes" or answer == "y":
			NewSectionSize = raw_input("["+G+"+"+W+"] Please enter new section size (default is 1000): ").lower()
			if not NewSectionSize:
				NewSectionSize = 1000
				print "["+G+"+"+W+"] Adding %i section to PE file.." %(NewSectionSize)
				time.sleep(1)
				AddSection(pe, NewSectionSize)
			else:	
				NewSectionSize = int(NewSectionSize)
				print "["+G+"+"+W+"] Adding %i section to PE file.." %(NewSectionSize)
				time.sleep(1)
				AddSection(pe, NewSectionSize)
		elif answer == "no" or answer == "n":
			pass
		else:
			print "Please enter Yes or No."

	# save changes to PE file logic
	answer = None
	while answer not in ("yes", "no", "y", "n"):
		answer = raw_input("["+G+"+"+W+"] Would you like to save changes? Enter Yes or No: ").lower()
		if answer == "yes" or answer == "y":
			print "["+G+"+"+W+"] Saving modified PE file.."
			time.sleep(1)
			SaveChanges(pe, file)
		elif answer == "no" or answer == "n":
			pass
		else:
			print "Please enter Yes or No."

if __name__ == '__main__':
	main()

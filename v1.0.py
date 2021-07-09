# -*- coding: utf-8 -*
from scapy.all import *
src = sys.argv[1]
dst = sys.argv[2]
dport = int(sys.argv[3])

message_str_origin = "0300001902f080320700000100000800080001120411440100ff09000400110000"
message_str = "0300001902f080320100000100000800080001120411440100ff09000400110000"


'''
generate fuzz data
'''
def generate_random_str(randomlength):
	random_str = ''
	base_str = 'abcdef0123456789'
	length = len(base_str) - 1
	for i in range(randomlength):
		random_str += base_str[random.randint(0, length)]
	return random_str

def generate_str_unpack(s):
	res = ""
	for i in range(len(s)):
		res2 = str(hex(s[i])[2:])
		if len(res2) != 2:
			res2 = '0' + res2
		res += res2
	return res


'''
hex_to_str
'''
def hex_to_str(s):
	list1 = []
	i = 0
	while i < len(s):
		list1.append(s[i] + s[i+1])
		i += 2
	return ''.join([chr(i) for i in [int(b, 16) for b in list1]])

def hex_to_str_unpack(s):
	list1 = []
	i = 0
	while i < len(s):
		list1.append(s[i] + s[i+1])
		i += 2
	return ''.join([chr(i) for i in [int(b, 16) for b in list1]])

def int_to_str_to_hex(s):
	hex_str = hex(int(len_sum))
	for i in range(len(hex_str)):
		if hex_str[i] == 'x':
			temp = i
	return hex_str[temp+1:]

'''
get s7 truly input data
'''
def get_s7_truly_data():
	pcaps = rdpcap("huxiao.pcapng")
	s7 = []
	for i in range(len(pcaps)):
		'''
		temp = pcaps[i].load
		temp_str_hex = generate_str_unpack(temp)
		temp_str = hex_to_str_unpack(temp_str_hex)
		'''
		catch_flag = 0
		try:
			pcaps[i].load
		except Exception as ValueError:
			pass
		else:
			if generate_str_unpack(pcaps[i].load)[0:6] == "030000" and catch_flag == 0:
				catch_flag += 1
			if generate_str_unpack(pcaps[i].load)[0:6] == "030000" and catch_flag == 1:
				catch_flag += 1
			if generate_str_unpack(pcaps[i].load)[0:6] == "030000" and catch_flag == 2:
				s7.append(i)
				catch_flag += 0
	return s7


'''
unpack and analyze the s7 protocol
'''



'''
fuzz data generate
'''
#-------------------------------------------------------------------head------------------------------------------------------------
def s7_head(data_len=0):
	len_sum = 25 + data_len
	len_sum_hex = int_to_str_to_hex(str(len_sum))

	TPKT_COTP = "0300" + len_sum_hex + "02f080"
	Protocol_ID   = "32"                    #protocol id:0x32
	ROSCTR_dict = {'0':"00",'1':"01"}       #PDU type
	ROSCTR = ROSCTR_dict[random.randint(0, 1)]
	Redundancy_Identification = "0000"

	Protocol_Data_Unit_Reference = generate_random_str(4)     #protocol data unit reference
	Parameter_Length = "0008"               #parameters length

	Head_Data_Length   = (
		hex(
			data_len
		)[2:]
	).zfill(4)   #d4ta length

	header = Protocol_ID + ROSCTR + Redundancy_Identification +   Protocol_Data_Unit_Reference + Parameter_Length +   Head_Data_Length
	replay_header = TPKT_COTP + header
	return replay_header


#-------------------------------------------------------------------paramaters----------------------------------------------------------
#0xF0_para connect generate
def s7_para_connect():
	function_code = "f0"     #actually oxf0 is the only correct data
	Reserved = "00"
	ack = "00010001"
	PDU_length = generate_random_str(4)
	replay_parameter = function_code + Reserved + ack + PDU_length
	return replay_parameter

#0x04_para generate
def s7_para_read():
	function_code = "04"
	item_num = generate_random_str(2)
	item_num_int = int(item_num,16)
	'''
	item part
	'''
	temp_item = ""
	for i in range(item_num_int):
		Variable_specification = "12"
		last_length = "0a"
		IDS_address = generate_random_str(2)
		data_transfer_size = generate_random_str(2)
		data_length = generate_random_str(4)
		da_numth = generate_random_str(4)   #not get db then use 0x0000
		area = generate_random_str(2)
		get_data_address = generate_random_str(6)
		temp_item = Variable_specification + last_length + IDS_address + data_transfer_size + data_length + da_numth + area + get_data_address

	replay_parameter = function_code + item_num + temp_item
	return replay_parameter

#0x05_para generate
def s7_para_write():
	function_code = "05"
	item_num = generate_random_str(2)
	item_num_int = int(item_num,16)
	'''
	item part
	'''
	temp_item = ""
	for i in range(item_num_int):
		Variable_specification = "12"
		last_length = "10"
		IDS_address = generate_random_str(2)
		data_transfer_size = generate_random_str(2)
		data_length = generate_random_str(4)
		da_numth = generate_random_str(4)   #not get db then use 0x0000
		area = generate_random_str(2)
		get_data_address = generate_random_str(6)
		temp_item = Variable_specification + last_length + IDS_address + data_transfer_size + data_length + da_numth + area + get_data_address

	replay_parameter = function_code + item_num + temp_item
	return replay_parameter

#0x1a_para generate
def s7_para_request_download():
	Variable_specification = "1a"
	function_state = "00"
	no_meaning = "010000000000"
	filename_length = "09"
	#filename
	file_id = "5f"       #file id
	Block_type = "3041"
	Block_num = "3030303031"
	target_filesystem = "50"
	file = file_id + Block_type + Block_num + target_filesystem
	#----
	second_lenth = "0d"
	unkown_char = "31"
	load_length = generate_random_str(12)
	MC7_length = generate_random_str(12)
	replay_parameter = Variable_specification + function_state + no_meaning + filename_length + file + second_lenth + unkown_char + load_length + MC7_length
	return replay_parameter

#0x1b_para generate
def s7_para_download():
	Variable_specification = "1b"
	function_state = "00"
	no_meaning = "010000000000"
	filename_length = "09"
	#filename
	file_id = "5f"       #file id
	Block_type = "3041"
	Block_num = "3030303031"
	target_filesystem = "50"
	file = file_id + Block_type + Block_num + target_filesystem
	#----
	replay_parameter = Variable_specification + function_state + no_meaning + filename_length + file
	return replay_parameter

#0x1c_para generate
def s7_para_download_end():
	Variable_specification = "1b"
	function_state = "00"
	no_meaning = "010000000000"
	filename_length = "09"
	#filename
	file_id = "5f"       #file id
	Block_type = "3041"
	Block_num = "3030303031"
	target_filesystem = "50"
	file = file_id + Block_type + Block_num + target_filesystem
	#----
	replay_parameter = Variable_specification + function_state + no_meaning + filename_length + file
	return replay_parameter

#0x1d_para generate
def s7_para_upload_request():
	Variable_specification = "1d"
	block_type = "0000"
	Block_num = "0000000000"
	Target_filesystem = "09"
	#filename
	file_id = "5f"       #file id
	Block_type = "3042"
	Block_num = "3030303030"
	target_filesystem = "41"
	file = file_id + Block_type + Block_num + target_filesystem
	#----
	replay_parameter = Variable_specification + block_type + Block_num + Target_filesystem + file
	return replay_parameter

#0x1e_para generate
def s7_para_upload():
	Variable_specification = "1e"
	function_state = "00"
	unkown_char = "0000"
	upload_id = "00000007"
	replay_parameter = Variable_specification + function_state + unkown_char + upload_id
	return replay_parameter

#0x1f_para generate
def s7_para_upload_end():
	Variable_specification = "1e"
	function_state = "00"
	unkown_char = "0000"
	upload_id = "00000007"
	error_code = "0000"
	replay_parameter = Variable_specification + function_state + unkown_char + error_code + upload_id
	return replay_parameter

#0x28_para generate
def s7_para_program_call():
	Variable_specification = "28"
	unkown_char = "000000000000fd"
	Parameter_block_Length = "02"
	Parameter_block = "4550"
	data_length = "05"
	service_name = generate_random_str(10)

#0x29_para generate
def s7_para_closeplc():
	Variable_specification = "29"
	unkown_char = "0000000000"
	service_length = "09"
	service_name = generate_random_str(18)


#-------------------------------------------------------------------data-----------------------------------------------------------
#0x05_data generate
def s7_data_write():
	Return_code = "00"
	Transport_type_size = generate_random_str(2)  #0x03 0x04 bit byte word...
	Data_length = generate_random_str(4)
	data = generate_random_str(Data_length)


#---------------------------------------------------------return package judge-------------------------------------------------------
#0xf0_return generate
def s7_return_connect(message):
	code = message[20:24]
	Error_type = code[0:2]
	error_code = code[2:]
	error_type_message = ""
	error_code_message = ""
	if Error_type != "00":
		if Error_type + error_code == "0110":
			print("Invalid block number")
		if Error_type + error_code == "0111":
			print("Invalid request length")
		if Error_type + error_code == "0112":
			print("Invalid parameters")
		if Error_type + error_code == "0113":
			print("Invalid block type")
		if Error_type + error_code == "0114":
			print("Cant find block")
		if Error_type + error_code == "0115":
			print("Block already exist")
		if Error_type + error_code == "0116":
			print("Block write protected")
		if Error_type + error_code == "0117":
			print("Block or system update too much")
		if Error_type + error_code == "0118":
			print("Invalid block number")
		if Error_type + error_code == "0119":
			print("Password error")
		if Error_type + error_code == "011A":
			print("PG resource error")
		if Error_type + error_code == "011B":
			print("PLC resource error")
		if Error_type + error_code == "011c":
			print("Protocol error")
		if Error_type + error_code == "011d":
			print("Too many blocks")
		if Error_type + error_code == "011e":
			print("Not connect to database or Invalid S7DOS")
		if Error_type + error_code == "011f":
			print("Buffer is too small")
		if Error_type + error_code == "0120":
			print("Block end list")
		if Error_type + error_code == "0140":
			print("Lack can use memory")
		if Error_type + error_code == "0141":
			print("Lack resources, cant process tasks")
		if Error_type + error_code == "8001":
			print("The block cant process request service in this state now")
		if Error_type + error_code == "8003":
			print("S7 protocol error, transfer block error")
		if Error_type + error_code == "8100":
			print("App common error, unknown remote service")
		if Error_type + error_code == "8104":
			print("Frame error or dont apply service on this part")
		if Error_type + error_code == "8204":
			print("Object type specification inconsistent")
		if Error_type + error_code == "8205":
			print("The copied block already exists and is not connected")
		if Error_type + error_code == "8301":
			print("The memory space or working memory on the module is insufficient, or the specified storage medium is not accessible")
		if Error_type + error_code == "8302":
			print("Too few available resources or unavailable processor resources")
		if Error_type + error_code == "8304":
			print("No further parallel uploads. There is a resource bottleneck")
		if Error_type + error_code == "8305":
			print("Function is not available")
		if Error_type + error_code == "8306":
			print("Insufficient working memory (for copying, linking, loading AWP)")
		if Error_type + error_code == "8307":
			print("Insufficient retentive working memory (for copying, linking, loading AWP)")
		if Error_type + error_code == "8401":
			print("S7 protocol error: invalid service sequence (for example, load or upload block)")
		if Error_type + error_code == "8402":
			print("The service cannot be executed due to the state of the addressed object")
		if Error_type + error_code == "8404":
			print("S7 protocol: the function cannot be performed")
		if Error_type + error_code == "8405":
			print("The remote block is in the DISABLE state (CFB). The function cannot be executed")
		if Error_type + error_code == "8500":
			print("S7 protocol error: frame error")
		if Error_type + error_code == "8503":
			print("Alert from module: service canceled prematurely")
		if Error_type + error_code == "8701":
			print("Error when addressing the object on the communication partner (for example, wrong area length)")
		if Error_type + error_code == "8702":
			print("The requested service is not supported by the module")
		if Error_type + error_code == "8703":
			print("Denied access to objects")
		if Error_type + error_code == "8704":
			print("Access error: object is corrupted")
		if Error_type + error_code == "d001":
			print("Protocol error: illegal job number")
		if Error_type + error_code == "d002":
			print("Parameter error: illegal job variant")
		if Error_type + error_code == "d003":
			print("Parameter error: the module does not support the debugging function")
		if Error_type + error_code == "d004":
			print("Parameter error: Illegal job status")
		if Error_type + error_code == "d005":
			print("Parameter error: Illegal job termination")
		if Error_type + error_code == "d006":
			print("Parameter error: illegal link disconnection ID")
		if Error_type + error_code == "d007":
			print("Parameter error: illegal number of buffer elements")
		if Error_type + error_code == "d008":
			print("Parameter error: illegal scan rate")
		if Error_type + error_code == "d009":
			print("Parameter error: illegal execution times")
		if Error_type + error_code == "d00a":
			print("Parameter error: illegal trigger event")
		if Error_type + error_code == "d00b":
			print("Parameter error: illegal trigger condition")
		if Error_type + error_code == "d011":
			print("Parameter error in the calling environment path: block does not exist")
		if Error_type + error_code == "d012":
			print("Parameter error: wrong address in the block")
		if Error_type + error_code == "d014":
			print("Parameter error: deleting/overwriting block")
		if Error_type + error_code == "d015":
			print("Parameter error: illegal label address")
		if Error_type + error_code == "d016":
			print("Parameter error: Cannot test the job due to user program error")
		if Error_type + error_code == "d017":
			print("Parameter error: illegal trigger number")
		if Error_type + error_code == "d025":
			print("Parameter error: invalid path")
		if Error_type + error_code == "d026":
			print("Parameter error: illegal access type")
		if Error_type + error_code == "d027":
			print("Parameter error: this number of data blocks is not allowed")
		if Error_type + error_code == "d031":
			print("Internal protocol error")
		if Error_type + error_code == "d032":
			print("Parameter error: the length of the result buffer is wrong")
		if Error_type + error_code == "d033":
			print("Protocol error: job length error")
		if Error_type + error_code == "d03f":
			print("Encoding error: error in the parameter part (for example, the reserved byte is not equal to 0)")
		if Error_type + error_code == "d041":
			print("Data error: Illegal status list ID")
		if Error_type + error_code == "d042":
			print("Data error: illegal label address")
		if Error_type + error_code == "d043":
			print("Data error: Cannot find the referenced job, check the job data")
		if Error_type + error_code == "d044":
			print("Data error: illegal tag value, check job data")
		if Error_type + error_code == "d045":
			print("Data error: ODIS control is not allowed to exit in HOLD")
		if Error_type + error_code == "d046":
			print("Data error: illegal measurement phase during run-time measurement")
		if Error_type + error_code == "d047":
			print("Data error: Illegal hierarchy in \"Read Job List\"")
		if Error_type + error_code == "d048":
			print("Data error: Illegal delete ID in \"Delete Job\"")
		if Error_type + error_code == "d049":
			print("Invalid replacement ID in \"Replacement\"")
		if Error_type + error_code == "d04a":
			print("Error while executing'program status'")
		if Error_type + error_code == "d05f":
			print("Encoding error: Error in the data part (for example, the reserved byte is not equal to 0,...)")
		if Error_type + error_code == "d061":
			print("Resource error: no memory space for job")
		if Error_type + error_code == "d062":
			print("Resource error: job list is full")
		if Error_type + error_code == "d063":
			print("Resource error: Trigger event occupied")
		if Error_type + error_code == "d064":
			print("Resource error: There is not enough memory space for a result buffer element")
		if Error_type + error_code == "d065":
			print("Resource error: not enough memory space for multiple result buffer elements")
		if Error_type + error_code == "d066":
			print("Resource error: The timer available for runtime measurement is occupied by another job")
		if Error_type + error_code == "d067":
			print("Resource error: Too many \"modify flags\" jobs (especially multiprocessor operations)")
		if Error_type + error_code == "d081":
			print("Functions not allowed in current mode")
		if Error_type + error_code == "d082":
			print("Mode error: unable to exit HOLD mode")
		if Error_type + error_code == "d0a1":
			print("Functions not allowed for the current protection level")
		if Error_type + error_code == "d0a2":
			print("Cannot run at the moment, because the running function will modify the memory")
		if Error_type + error_code == "d0a3":
			print("Too many \"modify flag\" jobs active on I/O (especially multiprocessor operations)")
		if Error_type + error_code == "d0a4":
			print("'Force' has been established")
		if Error_type + error_code == "d0a5":
			print("Can't find referenced assignment")
		if Error_type + error_code == "d0a6":
			print("Cannot disable/enable job")
		if Error_type + error_code == "d0a7":
			print("The job cannot be deleted, for example because the job is currently being read")
		if Error_type + error_code == "d0a8":
			print("The job cannot be replaced, for example because the job is currently being read or deleted")
		if Error_type + error_code == "d0a9":
			print("Unable to read the job, for example because the job is currently being deleted")
		if Error_type + error_code == "d0aa":
			print("Processing operation exceeds time limit")
		if Error_type + error_code == "d0ab":
			print("Invalid job parameters in process operation")
		if Error_type + error_code == "d0ac":
			print("Invalid job data in process operation")
		if Error_type + error_code == "d0ad":
			print("Operation mode set")
		if Error_type + error_code == "d0ae":
			print("The job is set up through a different connection and can only be processed through this connection")
		if Error_type + error_code == "d0c1":
			print("At least one error was detected when accessing the label")
		if Error_type + error_code == "d0c2":
			print("Switch to STOP / HOLD mode")
		if Error_type + error_code == "d0c3":
			print("At least one error was detected when accessing the tag. Mode change to STOP / HOLD")
		if Error_type + error_code == "d0c4":
			print("Timeout during runtime measurement")
		if Error_type + error_code == "d0c5":
			print("The display of the block stack is inconsistent because the block is deleted/reloaded")
		if Error_type + error_code == "d0c6":
			print("The job has been deleted because the job it refers to has been deleted")
		if Error_type + error_code == "d0c7":
			print("The job was automatically deleted due to exiting the STOP mode")
		if Error_type + error_code == "d0c8":
			print("\"Block Status\" aborted due to inconsistency between the test job and the running program")
		if Error_type + error_code == "d0c9":
			print("Exit the status area by resetting OB90")
		if Error_type + error_code == "d0ca":
			print("Read the label exit status range by resetting OB90 before exiting and accessing the error reading")
		if Error_type + error_code == "d0cb":
			print("The output of the peripheral output is disabled and activated again")
		if Error_type + error_code == "d0cc":
			print("The data volume of the debugging function is limited by time")
		if Error_type + error_code == "d201":
			print("Syntax error in block name")
		if Error_type + error_code == "d202":
			print("Syntax error in function parameter")
		if Error_type + error_code == "d205":
			print("Link block already exists in RAM: conditional copy cannot be performed")
		if Error_type + error_code == "d206":
			print("Link block already exists in EPROM: conditional copy cannot be performed")
		if Error_type + error_code == "d208":
			print("Maximum number of copied (unlinked) blocks for the module exceeded")
		if Error_type + error_code == "d209":
			print("(At least) one of the given blocks could not be found on the module")
		if Error_type + error_code == "d20a":
			print("Exceeded the maximum number of blocks that can be linked with a job")
		if Error_type + error_code == "d20b":
			print("Exceeded the maximum number of blocks that can be deleted in a job")
		if Error_type + error_code == "d20c":
			print("OB cannot be copied because the associated priority does not exist")
		if Error_type + error_code == "d20d":
			print("SDB cannot explain (for example, unknown)")
		if Error_type + error_code == "d20e":
			print("No (further) blocking available")
		if Error_type + error_code == "d20f":
			print("Exceeding the module-specific maximum block size")
		if Error_type + error_code == "d210":
			print("Invalid block number")
		if Error_type + error_code == "d212":
			print("Incorrect header attributes (related to runtime)")
		if Error_type + error_code == "d213":
			print("Too many SDBs. Please note the restrictions on the modules being used")
		if Error_type + error_code == "d216":
			print("Invalid user program-reset module")
		if Error_type + error_code == "d217":
			print("The protection level specified in the module properties is not allowed")
		if Error_type + error_code == "d218":
			print("Incorrect attributes (active/passive)")
		if Error_type + error_code == "d219":
			print("Incorrect block length (for example, the length of the first part or the entire block is incorrect)")
		if Error_type + error_code == "d21a":
			print("Incorrect local data length or write protection error")
		if Error_type + error_code == "d21b":
			print("The module cannot compress or compress early interrupts")
		if Error_type + error_code == "d21d":
			print("The amount of dynamic project data transferred is illegal")
		if Error_type + error_code == "d21e":
			print("It is not possible to assign parameters to the module (eg FM, CP). System data cannot be linked")
		if Error_type + error_code == "d220":
			print("The programming language is invalid. Please note the restrictions on the modules being used")
		if Error_type + error_code == "d221":
			print("Invalid connection or routing system data")
		if Error_type + error_code == "d222":
			print("System data defined by global data contains invalid parameters")
		if Error_type + error_code == "d223":
			print("The instance data block of the communication function block is wrong or exceeds the maximum number of instance data blocks")
		if Error_type + error_code == "d224":
			print("SCAN system data block contains invalid parameters")
		if Error_type + error_code == "d225":
			print("The DP system data block contains invalid parameters")
		if Error_type + error_code == "d226":
			print("A structural error occurred in the block")
		if Error_type + error_code == "d230":
			print("A structural error occurred in the block")
		if Error_type + error_code == "d231":
			print("At least one loaded OB cannot be copied because the associated priority does not exist")
		if Error_type + error_code == "d232":
			print("At least one block number of the loaded block is illegal")
		if Error_type + error_code == "d234":
			print("The block exists twice in the specified memory medium or job")
		if Error_type + error_code == "d235":
			print("The block contains an incorrect checksum")
		if Error_type + error_code == "d236":
			print("The block does not contain a checksum")
		if Error_type + error_code == "d237":
			print("You are about to load the block twice, ie a block with the same time stamp already exists on the CPU")
		if Error_type + error_code == "d238":
			print("At least one of the specified blocks is not a DB")
		if Error_type + error_code == "d239":
			print("At least one specified DB cannot be used as a link variable in the load memory")
		if Error_type + error_code == "d23a":
			print("At least one specified DB is very different from the copy and link variants")
		if Error_type + error_code == "d240":
			print("Violation of coordination rules")
		if Error_type + error_code == "d241":
			print("The current protection level does not allow this feature")
		if Error_type + error_code == "d242":
			print("Protection conflict when processing F block")
		if Error_type + error_code == "d250":
			print("Update and module ID or version do not match")
		if Error_type + error_code == "d251":
			print("Operating system component sequence is incorrect")
		if Error_type + error_code == "d252":
			print("Checksum error")
		if Error_type + error_code == "d253":
			print("There is no executable loader available; only the memory card can be used for updates")
		if Error_type + error_code == "d254":
			print("Storage error in the operating system")
		if Error_type + error_code == "d280":
			print("Error when compiling blocks in S7-300 CPU")
		if Error_type + error_code == "d2a1":
			print("Another block function or trigger on the block is active")
		if Error_type + error_code == "d2a2":
			print("The trigger on the block is active. First complete the debugging function")
		if Error_type + error_code == "d2a3":
			print("The block is not activated (linked), the block is occupied or the block is currently marked for deletion")
		if Error_type + error_code == "d2a4":
			print("The block has been processed by another block function")
		if Error_type + error_code == "d2a6":
			print("Cannot save and change the user program at the same time")
		if Error_type + error_code == "d2a7":
			print("Block has \"unlinked\" attribute or is not processed")
		if Error_type + error_code == "d2a8":
			print("Activated commissioning function prevents parameter assignment to the CPU")
		if Error_type + error_code == "d2a9":
			print("New parameters are being assigned to the CPU")
		if Error_type + error_code == "d2aa":
			print("Currently assigning new parameters to the module")
		if Error_type + error_code == "d2ab":
			print("Currently changing dynamic configuration limits")
		if Error_type + error_code == "d2ac":
			print("A running activation or deactivation assignment (SFC 12) temporarily prevents the R-KiR process")
		if Error_type + error_code == "d2b0":
			print("An error occurred during configuration in RUN (CiR)")
		if Error_type + error_code == "d2c0":
			print("The maximum number of technology objects has been exceeded")
		if Error_type + error_code == "d2c1":
			print("The same technical data block already exists on the module")
		if Error_type + error_code == "d2c2":
			print("Unable to download user program or download hardware configuration")
		if Error_type + error_code == "d401":
			print("Information function is not available")
		if Error_type + error_code == "d402":
			print("Information function is not available")
		if Error_type + error_code == "d403":
			print("Service logged in/out (diagnostics/PMC)")
		if Error_type + error_code == "d404":
			print("The maximum number of nodes reached. No longer need to log in to diagnostics/PMC")
		if Error_type + error_code == "d405":
			print("Syntax errors in service or function parameters are not supported")
		if Error_type + error_code == "d406":
			print("Required information not currently available")
		if Error_type + error_code == "d407":
			print("A diagnostic error occurred")
		if Error_type + error_code == "d408":
			print("Update aborted")
		if Error_type + error_code == "d409":
			print("DP bus error")
		if Error_type + error_code == "d601":
			print("Syntax error in function parameter")
		if Error_type + error_code == "d602":
			print("The entered password is incorrect")
		if Error_type + error_code == "d603":
			print("The connection is legalized")
		if Error_type + error_code == "d604":
			print("Connection enabled")
		if Error_type + error_code == "d605":
			print("Since the password does not exist, it cannot be legalized")
		if Error_type + error_code == "d801":
			print("At least one tag address is invalid")
		if Error_type + error_code == "d802":
			print("The specified job does not exist")
		if Error_type + error_code == "d803":
			print("Illegal work status")
		if Error_type + error_code == "d804":
			print("Illegal cycle time (illegal time base or multiple)")
		if Error_type + error_code == "d805":
			print("Can no longer set a circular read job")
		if Error_type + error_code == "d806":
			print("The referenced job is in a state where the requested function cannot be performed")
		if Error_type + error_code == "d807":
			print("The function is aborted due to overload, which means that the time required to execute the read cycle is longer than the set scan cycle time")
		if Error_type + error_code == "dc01":
			print("Invalid date and/or time")
		if Error_type + error_code == "e201":
			print("CPU is already the main device")
		if Error_type + error_code == "e202":
			print("Because the user program in the flash memory module is different, it cannot be connected and updated")
		if Error_type + error_code == "e203":
			print("Unable to connect and update due to different firmware")
		if Error_type + error_code == "e204":
			print("Unable to connect and update due to different memory configurations")
		if Error_type + error_code == "e205":
			print("Connection/update aborted due to synchronization error")
		if Error_type + error_code == "e206":
			print("Connection/update refused due to coordination violation")
		if Error_type + error_code == "ef01":
			print("S7 protocol error: ID2 error; only 00H is allowed in work")
		if Error_type + error_code == "ef02":
			print("S7 protocol error: ID2 error; resource set does not exist")


#-------------------------------------------------------------------fuzz----------------------------------------------------------
def fuzz(message_str):
	fuzzpkt = TCP(sport=sport, dport=dport, flags='PA',seq=result[0][1][1].ack,ack=result[0][1][1].seq + len(result[0][1][1].load))
	fuzzsr = sr(ip/fuzzpkt/self, multi=True, timeout=5)

def tcpConnect():
	SYN = TCP(sport=sport, dport=dport, flags='S', seq=0)
	SYNACK = sr1(ip / SYN, timeout=1)   #第一次握手，发送SYN包
	ACK = TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
	send(ip / ACK)
	print('TCP connect success!')
	return SYNACK

def hello_plc(SYNACK):
	hello_data = hello
	comm_data = set_comm
	protocol="\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x01"
	
	hello_packet = TCP(sport=sport, dport=dport, flags='PA', seq=SYNACK.ack, ack=SYNACK.seq + 1)                #第一个COTP,S7
	COTPACK = sr1(ip / hello_packet / hello_data, multi=True, timeout=5)
	print('--------------')
	
	comm_pkt = TCP(sport=sport, dport=dport, flags='PA',seq=COTPACK.ack, ack=COTPACK.len + COTPACK.seq - 40)
	proto_2 = "\x03\x00\x00\x19\x02\xf0\x80\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0"
	COMMACK = sr1(ip / comm_pkt / comm_data, multi=True, timeout=5)
	print('------------------')
	comm_ack = TCP(sport=sport, dport=dport, flags='A',seq=COMMACK.ack, ack=COMMACK.len + COMMACK.seq - 40)
	#print(comm_ack)
	send(ip/comm_ack)
	print('PLC connect success!')
	return COMMACK




if __name__ == '__main__':
	#hello_input = "0300001611e00000000100c0010ac1020100c2020101"
	hello_input = "0300001611e00000000100c0010ac1020102c2020101"
	set_comm_input = "0300001902f08032010000040000080000f0000001000101e0"
	sport = random.randint(1024, 65535)
	ip = IP(src=src, dst=dst)
	SYNACK = tcpConnect()
	print('TCP connect end!')
	print('--------------------------------------------------------------------------\n')
	''' test connect
	hello = hex_to_str(hello_input)
	set_comm = hex_to_str(set_comm_input)
	result = hello_plc(SYNACK)
	'''
	message = s7_head() + s7_para_data() + s7_data()
	message_str = hex_to_str(message)
	fuzz(message_str)
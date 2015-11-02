# DIBF #

Windows Driver IOCTL Tool Suite.

## DIBF ##
### Dynamic Ioctl Brute-Forcer (and fuzzers) ###
This tool encompasses two distinct features. It guesses the IOCTL values that the driver accepts and also their valid size limitations and store the results are in a file for future reuse. The second feature is comprised of 3 dumb fuzzers: a pure random fuzzer, a sliding DWORD fuzzer and an asynchronous fuzzer. You can run any combination of the 3 sequentially and can set time limits for each fuzzer run. The sync fuzzers will also warn you if too many requests fail in a row (indicating further fuzzing might be pointless due to lack permission for instance) and the async fuzzer allows you to set the percentage of requests to attempt cancelation on and the concurrency level (how many pending requests at once).  Other features include control over the verbosity level  and the ability to stop any fuzzer run cleanly with ctrl-c. Upon completion each fuzzer will display cumulative statistics.

### Usage ###
	dibf.exe <options> <device name>
	Options:
		-h You're looking at it
 		-i Ignore previous logfile - THIS WILL OVERWRITE IT
 		-l Specify custom logfile name to read from/write to (default dibf-bf-results.txt)
 		-d Deep IOCTL bruteforce (8-9 times slower)
 		-v [0-3] Verbosity level
 		-s [ioctl] Start IOCTL value
 		-e [ioctl] End IOCTL value
 		-t [d1,d2,d4] Timeout for each fuzzer in seconds -- no spaces and decimal input ONLY
 		-p [max requests] Max number of async pending requests (loosely enforced, default 64)
 		-a [max threads] Max number of threads, default is 2xNbOfProcessors, max is 128
 		-c [% cancelation] Async cancelation attempt percent rate (default 15)
 		-f [0-7] Fuzz flag. OR values together to run multiple
				 fuzzer stages. If left out, it defaults to all
          		 stages.
          0 = Brute-force IOCTLs only
          1 = Sliding DWORD (sync)
          2 = Random (async)
          4 = Named Pipe (async)
	Examples:
		dibf \\.\MyDevice
		dibf -v -d -s 0x10000000 \\.\MyDevice
		dibf -f 0x3 \\.\MyDevice
	Notes:
 		- The bruteforce stage will generate a file named "dibf-bf-results.txt"
   		  in the same directory as the executable. If dibf is started with no
   		  arguments, it will look for this file and start the fuzzer with the values
   		  from it The -l flag can be used to specify a custom results file name.
 		- If not specified otherwise, command line arguments can be passed as decimal or hex (prefix with "0x")
 		- CTRL-C interrupts the current stage and moves to the next if any. Current statistics will be displayed.
 		- The statistics are cumulative.
 		- The command-line flags are case-insensitive.

### Using the Named Pipe fuzzing provider ###

In order to provide fuzzed packet to the Named Pipe fuzzer, connect to `\\.\pipe\dibf_pipe` in *PIPE\_TYPE\_MESSAGE*
mode and send the fuzzed data. The last 4 bytes of the packet will be interpreted as the IOCTL code. Additionally the named pipe peach publisher can be used to fuzz named pipe endpoints outside of DIBF scope.

#### Connecting to Peach ####
The provided Peach publisher can be used to connect Peach to the DIBF's Named Pipe Fuzzing Provider. A sample Peach XML file `peach_np.xml` leveraging this provider can be found under the PeachNamedPipePublisher folder:

	<?xml version="1.0" encoding="utf-8"?>
	<Peach xmlns="http://peachfuzzer.com/2012/Peach" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	    xsi:schemaLocation="http://peachfuzzer.com/2012/Peach ../peach.xsd">

	    <!-- DataModel containing a single string -->
	    <DataModel name="TheDataModel">
	        <String value="Hello World!" />
	        <Number name="IOCTL0" value="EFBEADDE" valueType="hex" size="32" mutable="false" />
	    </DataModel>

	    <!-- StateModel referencing data model above -->
	    <StateModel name="DibfState" initialState="DibfState0">
	        <State name="DibfState0">
	            <Action type="output">
	                <DataModel ref="TheDataModel"/>
	            </Action>
	        </State>
	    </StateModel>

	    <!-- The test with pipe publisher -->
	    <Test name="Default">
	        <StateModel ref="DibfState"/>
	        <Publisher class="NamedPipe">
	            <Param name="host" value="." />
	            <Param name="pipeName" value="dibf_pipe" />
	            <Param name="impersonationLevel" value="1" />
	        </Publisher>
	    </Test>
	</Peach>
	<!-- end -->

### DIBF Sample Output ###

	<<<< RUNNING RANDOM FUZZER >>>>
	RUN STARTED: 3/17/2014 4:14 PM
	---------------------------------------
	Sent Requests : 4233
	Completed Requests : 4233 (4233 sync, 0 async)
	SuccessfulRequests : 1254
	FailedRequests : 2979
	CanceledRequests : 0
	RUN ENDED: 3/17/2014 4:14 PM
	---------------------------------------
	
	<<<< RUNNING SLIDING DWORD FUZZER >>>>
	RUN STARTED: 3/17/2014 4:14 PM
	---------------------------------------
	Sent Requests : 6339
	Completed Requests : 6339 (6339 sync, 0 async)
	SuccessfulRequests : 1254
	FailedRequests : 5085
	CanceledRequests : 0
	RUN ENDED: 3/17/2014 4:14 PM
	---------------------------------------

	<<<< RUNNING ASYNC FUZZER >>>>
	RUN STARTED: 3/17/2014 4:14 PM
	---------------------------------------
	Sent Requests : 8272
	Completed Requests : 8272 (6339 sync, 1933 async)
	SuccessfulRequests : 1738
	FailedRequests : 6414
	CanceledRequests : 120
	RUN ENDED: 3/17/2014 4:14 PM
	---------------------------------------

## IOCODE ##
### Simple encoding/decoding utility for IO codes ###
This very simple tool encodes and decodes windows IOCTL control codes. It provides a user-friendly way to deal with IO encoding of device types, function number, transfer method and access type.

	iocode.exe [IOCODE] or iocode.exe [DEVICE_TYPE] [FUNCTION] [METHOD] [ACCESS]

## IOSEND ##
### Sending single IOCTL to a driver ###
This is a tool intended for proofing vulnerabilities and is meant to be used in conjunction with a hex-editor. Once the request of interest has been crafted in it, this utility will send it to the driver using command line parameters. The response gets sent to stdout. Arbitrary addresses can also be used as input and output buffer addresses.

	iosend [Device] [IOCODE] [InputBufFilePath|InputAdress] [InputLen] [[OutputAddress]] [OutputLen] > [Output file]
	Notes:
	 - This utility prints error/status messages to stderr
	 - Input can be provided as an arbitrary address or a file name
	 - An output buffer is allocated and its contents eventually written to stdout unless the optional OutputAddress parameter is provided

License
-------------
GPLv2


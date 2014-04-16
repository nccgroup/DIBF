DIBF
======

Windows Driver IOCTL Tool Suite.

Description
-----------
DIBF .exe – Dynamic Ioctl Brute-Forcer (and fuzzers)
This tool encompasses two distinct features. It guesses the IOCTL values that the driver accepts and also their valid size limitations and store the results are in a file for future reuse. The second feature is comprised of 3 dumb fuzzers: a pure random fuzzer, a sliding DWORD fuzzer and an asynchronous fuzzer. You can run any combination of the 3 sequentially and can set time limits for each fuzzer run. The sync fuzzers will also warn you if too many requests fail in a row (indicating further fuzzing might be pointless due to lack permission for instance) and the async fuzzer allows you to set the percentage of requests to attempt cancelation on and the concurrency level (how many pending requests at once).  Other features include control over the verbosity level  and the ability to stop any fuzzer run cleanly with ctrl-c. Upon completion each fuzzer will display cumulative statistics.

IOSEND.exe – sending single IOCTL to a driver
This is a tool intended for proofing vulnerabilities and is meant to be used in conjunction with a hex-editor. Once the request of interest has been crafted in it, this utility will send it to the driver using command line parameters. The response gets sent to stdout.

IOCODE.exe – simple encoding/decoding utility for IO codes
This very simple tool encodes and decodes windows IOCTL control codes. It provides a user-friendly way to deal with IO encoding of device types, , function number, transfer method and access type.

Usage
-------------
dibf.exe <options> <device name>
Options:
 -h You're looking at it
 -i Ignore previous logfile - THIS WILL OVERWRITE IT
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
          1 = Random
          2 = Sliding DWORD
          4 = Async / Pending
Examples:
 dibf \\.\MyDevice
 dibf -v -d -s 0x10000000 \\.\MyDevice
 dibf -f 0x3 \\.\MyDevice
Notes:
 - The bruteforce stage will generate a file named "dibf-bf-results.txt"
   in the same directory as the executable. If dibf is started with no
   arguments, it will look for this file and start the fuzzer with the values
   from it.
 - If not specified otherwise, command line arguments can be passed as decimal or hex (prefix with "0x")
 - CTRL-C interrupts the current stage and moves to the next if any. Current statistics will be displayed.
 - The statistics are cumulative.
 - The command-line flags are case-insensitive.

-------------
iocode.exe [IOCODE] or iocode.exe [DEVICE_TYPE] [FUNCTION] [METHOD] [ACCESS]

-------------
iosend.exe [Device] [IOCODE] [InputBufFilePath] [InputLen] [OutputLen] > [Output file]
Notes:
 - This utility prints error/status messages to stderr
 - Upon successful IOCTL, output data is written to stdout


DIBF Sample Output
-------------
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


License
-------------
GPLv2

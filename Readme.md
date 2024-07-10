# StringPool Viewer
## info
+ this tool supports only x64 unpacked client now.
	+ neckson stopped packing game client from 1~2 years ago. you do not need to unpack client files.
	+ this tool does not support memory dump. if you want to use unpacked client, you have to unpack it correctly.
		+ if you do not have knowledge for unpacking client, please make memory dump and fix section header's RawAddress value to Virtual Address Value.
+ tested
	+ JMS v425.1
	+ TWMS v261.4
	+ KMS v2.388.1
	+ MSEA v234.1

## how to use?
+ drag and drop x64 version of game client file to window.
+ Manual
	+ enter StringPool Array address and press Load.
+ Auto (AobScan)
	+ press scan button to get tringPool Array address and press load button.
+ Dump
	+ you can dump string data after this tool loads StringPool data.

## TODO
+ string search/filter
+ auto array size search
+ string replacement
+ x86 client support
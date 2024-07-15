# StringPool Viewer
## info
+ this tool may work for all x86 unpacked client. but some client may have different encryption or do not use StringPool, this does not work for those clients.
+ x64 Aob supports few version of client, it often changes by updates and this is hard to make aob.
+ tested
	+ JMS v161~v336, v425
	+ TWMS v106~v122, v142, v261
	+ CMS v79~v95, v208
	+ KMS v2.65~v2.109, v2.380~v2.388
	+ KMST v2.421, v2.1173
	+ MSEA v234
	+ GMS v90, v95
	+ EMS v101
+ not work
	+ EMS v70
	+ MSEA v102

## how to use?
+ drag and drop unpacked game client file to window. current x64 client is not packed.
+ Manual
	+ enter StringPool Array address and press Load.
+ Auto (AobScan)
	+ press scan button to get tringPool Array address and press load button.
+ Dump
	+ you can dump string data after this tool loads StringPool data.

## TODO
+ string search/filter
+ string replacement
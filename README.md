## BinaryNinja Windows API Annotator

Run this plugin to annotate Windows API function call parameters.

This plugin runs over only the selected function instead all functions; this is to prevent significant slow downs. 

### Supported modules

* kernel32.dll
* user32.dll
* ole32.dll
* advapi32.dll

Please feel free to create issues to request more modules. I wrote a script to parse DLLs for their exports and query msdn for the function params. It's pretty good at it.

### Disclaimer

The json data is formatted in `sdb` format, created by the radare2 team (see https://radare.gitbooks.io/radare2book/basic_commands/sdb.html for more info). Some of the function param information comes directly from the `types-windows.sdb.txt` file seen [here](https://github.com/radare/radare2/tree/master/libr/anal/d). I used their `sdb` tool to output the database in json format, and then I copied my previous json files into it.

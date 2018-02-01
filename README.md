## BinaryNinja Windows API Annotator

Annotate Windows API function call parameters! Big thanks to @carstein for setting the foundation.

### Supported modules
* kernel32.dll
* user32.dll
* ole32.dll
* advapi32.dll

#### Please feel free to submit requests for more modules!

### Disclaimer
* I cannot guarentee this project is issue-free
* More users will help us figure out where the bugs are, and so I'm opening this up already in its alpha-y state
* I wrote my own WinAPI parser, and so far, I haven't run into any major errors
    * ...but I can only reverse so many windows binaries in a day, after all
    * I have seen a few small-ish issues (e.g., missing star characters for pointers, the occasional leftever "_opt"), but PLEASE feel free to let me know of any others you see and I will take care of them
    * I will also keep working on my parser to make subsequent modules less error-prone
* One last thing -- this plugin runs over only the selected function instead all functions; this is to prevent in significant slow downs 




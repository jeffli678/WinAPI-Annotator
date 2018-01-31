## BinaryNinja Windows-Annotator

Annotate Windows API function call parameters! Big thanks to @carstein for setting the foundation.

### Supported modules
* kernel32.dll
* user32.dll
* ole32.dll
* advapi32.dll

#### Please feel free to submit requests for more modules!

### Disclaimer
* I cannot guarentee this project is issue-free
* I wrote my own WinAPI parser, and so far, I haven't run into any major errors
    * ...but I can only reverse so many windows binaries in a day, after all
    * I have seen a few small-ish issues (e.g., missing star characters for pointers, the occasional leftever "_opt"), but PLEASE feel free to let me know of any others you see and I will take care of them
    * I will also keep working on my parser to make subsequent modules less error-prone
* One last thing -- this plugin runs over *all* functions instead of the selected function, so you might encounter a slight lag depending on which version you have (commercial or personal) and how big the PE file being analyzed is




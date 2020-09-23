                            _____       _         _           _         
         /\                / ____|     | |       | |         | |        
        /  \   _ __  _ __ | |  __  __ _| |_ ___  | |     __ _| |__  ___ 
       / /\ \ | '_ \| '_ \| | |_ |/ _` | __/ _ \ | |    / _` | '_ \/ __|
      / ____ \| |_) | |_) | |__| | (_| | ||  __/ | |___| (_| | |_) \__ \
     /_/    \_\ .__/| .__/ \_____|\__,_|\__\___| |______\__,_|_.__/|___/
              | |   | |                                                 
              |_|   |_|    

# Dridex

This repository contains files related to Dridex vaccine.

## Vaccine

The "compiled" directory contains Dridex vaccine for shell32.dll

To deploy the vaccine simply drop it into SysWOW64 (for x64 Windows) or system32 (for x86 Windows).

The filename is not random, the name is a CRC32 collision (when uppercase) for shell32.dll, is expected to be loaded by the Dridex loader when trying to find shell32.dll

```
crc32(b'SHELL32.DLL')
0x23FDAD3C
crc32(b'HHDK0GU.DLL')
0x23FDAD3C
```

## Source Files

The "Source" directory contains the source files for the vaccine, it can be compiled using VSCode or VisualStudio on Windows. 

The "exports.def" file maps the hook_stub into shell32.dll export table, you can change that to match any other DLL loaded from the disk by Dridex to create a vaccine, just be sure to change the name to a CRC32 collision of the desired DLL.

## POC

The "poc" directory contains the video of the vaccine working, and also the test files.

**WARNING!** The poc.zip contains a compiled version of the vaccine and also a **real Dridex payload** for testing purposes, be careful!

Zip password: infected
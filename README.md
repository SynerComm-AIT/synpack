# synpack

Simple packer that executes .NET binaries in memory. It can AES encrypt a .NET binary and embed it into the synpack binary, decrypting and executing in memory. Or it can download the .NET binary from a remote URL (encrypted or unencrypted) and execute it in memory that way.

* Patches AMSI and ETW
* All functions and some select variables are replaced with random strings

1. Ensure Rust is installed: https://www.rust-lang.org/tools/install
2. Install Perl (Windows): https://strawberryperl.com/

Run the perl script and follow the prompts.

```
perl .\synpack.pl
 ____                               _
/ ___| _   _ _ __  _ __   __ _  ___| | __
\___ \| | | | '_ \| '_ \ / _` |/ __| |/ /
 ___) | |_| | | | | |_) | (_| | (__|   <
|____/ \__, |_| |_| .__/ \__,_|\___|_|\_\
       |___/      |_|
 v0.1

Usage: perl .\synpack.pl <path or url to exe> <arguments>
(You can also omit the arguments and pass them directly to the binary)
```

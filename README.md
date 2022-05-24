# py-hvtool-ce7

This is a small python script for attempting to parse Windows CE 7 registry
hives.

This script is heavily influenced by Willem Jan Hengeveld's
<https://github.com/nlitsme/hvtool> (commit
b639d697fb18fcf4c400ff67ef0581cd5f9ee452). This script is essentially a
dependency-less rewrite of hvtool for python, with some adjustments to work
for hive files from CE 7 systems (rather than CE 6 like in the original
hvtool).

Note that this has only been tested on the registry hives (system.hv and
user.hv) of a single Beckhoff CX9020 PLC. It might not work for other devices
and the interpretation made by this tool may be wrong or incomplete.

Note also that the code has been intentionally shortened to fit inside better
in a PDF.

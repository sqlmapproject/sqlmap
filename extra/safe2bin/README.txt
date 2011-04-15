To use safe2bin.py you need to pass it the original file,
and optionally the output file name.

Example:

$ python ./safe2bin.py -i output.txt -o output.txt.bin

This will create an binary decoded file output.txt.bin. For example, 
if the content of output.txt is: "\ttest\t\x32\x33\x34\nnewline" it will 
be decoded to: "    test   234
newline"

If you skip the output file name, general rule is that the binary
file names are suffixed with the string '.bin'. So, that means that 
the upper example can also be written in the following form:

$ python ./safe2bin.py -i output.txt

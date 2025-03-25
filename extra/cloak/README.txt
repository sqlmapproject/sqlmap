To use cloak.py you need to pass it the original file,
and optionally the output file name.

Example:

$ python ./cloak.py -i backdoor.asp -o backdoor.asp_

This will create an encrypted and compressed binary file backdoor.asp_.

Such file can then be converted to its original form by using the -d
functionality of the cloak.py program:

$ python ./cloak.py -d -i backdoor.asp_ -o backdoor.asp

If you skip the output file name, general rule is that the compressed
file names are suffixed with the character '_', while the original is
get by skipping the last character. So, that means that the upper
examples can also be written in the following form:

$ python ./cloak.py -i backdoor.asp

$ python ./cloak.py -d -i backdoor.asp_

Due to the anti-virus positive detection of executable stored inside this
folder, we needed to somehow circumvent this. As from the plain sqlmap
users perspective nothing has to be done prior to its usage by sqlmap, but
if you want to have access to the original executable use the decrypt
functionality of the ../extra/cloak/cloak.py utility.

To prepare the executable to the cloaked form use this command:
python ../extra/cloak/cloak.py -i Churrasco.exe

To get back the original executable use this:
python ../extra/cloak/cloak.py -d -i Churrasco.exe_

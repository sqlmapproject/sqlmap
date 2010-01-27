Due to the anti-virus positive detection of shell scripts stored inside this folder, 
we needed to somehow circumvent this. As from the plain sqlmap users perspective nothing
has to be done prior to their usage by sqlmap, but if you want to have access to their
original source code use the decrypt functionality of the ../extra/cloak/cloak.py utility.

To prepare the original scripts to the cloacked form use this command:
find backdoor.* uploader.* -type f -exec python ../extra/cloak/cloak.py -i '{}' \;

To get back them into the original form use this:
find backdoor.*_ uploader.*_ -type f -exec python ../extra/cloak/cloak.py -d -i '{}' \;
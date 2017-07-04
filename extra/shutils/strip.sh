#!/bin/bash

# References:   http://www.thegeekstuff.com/2012/09/strip-command-examples/
#               http://www.muppetlabs.com/~breadbox/software/elfkickers.html
#               https://ptspts.blogspot.hr/2013/12/how-to-make-smaller-c-and-c-binaries.html

# For example:
# python ../../../../../extra/cloak/cloak.py -d -i lib_postgresqludf_sys.so_
# ../../../../../extra/shutils/strip.sh lib_postgresqludf_sys.so
# python ../../../../../extra/cloak/cloak.py -i lib_postgresqludf_sys.so
# rm lib_postgresqludf_sys.so

strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag $*
sstrip $*


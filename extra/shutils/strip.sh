#!/bin/bash

# References:   http://www.thegeekstuff.com/2012/09/strip-command-examples/
#               http://www.muppetlabs.com/~breadbox/software/elfkickers.html
#               https://ptspts.blogspot.hr/2013/12/how-to-make-smaller-c-and-c-binaries.html

# https://github.com/BR903/ELFkickers/tree/master/sstrip
# https://www.ubuntuupdates.org/package/core/cosmic/universe/updates/postgresql-server-dev-10

# For example:
# python ../../../../../extra/cloak/cloak.py -d -i lib_postgresqludf_sys.so_
# ../../../../../extra/shutils/strip.sh lib_postgresqludf_sys.so
# python ../../../../../extra/cloak/cloak.py -i lib_postgresqludf_sys.so
# rm lib_postgresqludf_sys.so

strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag $*
sstrip $*


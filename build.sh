#!/bin/bash
#
# This is a pecular build order. It has to do with the .text segment
# being known by both aud and bldaudtab so that an internal
# audit of aud can be done at startup.
#
rm -f bldaudtab.o
make bldaudtab
./bldaudtab
make aud
rm -f bldaudtab.o
make bldaudtab
./bldaudtab
make aud

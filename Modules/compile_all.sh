#!/bin/bash
for d in *.bundle/ ; do (cd $d && make clean && make package FINALPACKAGE=1 && cd ../) done

#!/bin/bash
mkdir -p packages
rm -f packages/*
for d in *.bundle/ ; do (cd $d && make clean && make package FINALPACKAGE=1 && cp -p "`ls -dtr1 packages/* | tail -1`" ../packages/ && cd ../) done

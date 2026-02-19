#!/bin/sh

echo "*** Testing for heap block overruns..."
efrpctest
if [ $? -ne 0 ]; then exit 1; fi
 
echo "*** Testing for heap block underruns..."
EF_PROTECT_BELOW=1 efrpctest
if [ $? -ne 0 ]; then exit 1; fi

echo "*** Testing for access to freed heap blocks..."
EF_PROTECT_FREE=1 efrpctest
if [ $? -ne 0 ]; then exit 1; fi

echo "*** Testing for single-byte overruns..."
EF_ALIGNMENT=0 efrpctest
if [ $? -ne 0 ]; then exit 1; fi

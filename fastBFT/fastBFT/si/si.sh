#!/bin/sh
#参数个数
paramCount=$1
#gnome-terminal -x "./si"
printf "paramCount=$paramCount\n"

for (( i = 1; i <= $paramCount; i++ )); do
    #statements
	#echo ${!i}
	#gnome-terminal -x "./si"
	./si $2 &
done

#!/usr/bin/bash

if [ -z "${1}" ] || [ $# -eq 0 ];
then
    printf "%s: %s\n" "$(color -r "Error")" "$(color -w "Expecting an argument")"
else
    sudo lsof -i | grep "${1}"
fi


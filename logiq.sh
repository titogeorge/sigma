#!/bin/sh

for filename in $(find ./rules -name '*.yml' );do \
#    echo "Generating for ${filename}"
    /home/tito/.local/share/virtualenvs/sigma-L5uM1Jne/bin/python /home/tito/tools/sigma/tools/sigmac --target logiq  "${filename}"
#    printf "====================\n\n"
done
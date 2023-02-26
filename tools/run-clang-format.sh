#!/bin/bash


# Runs clang-format only on modified files.
for file in $(git diff --name-only --diff-filter=ACMRTUXB | grep -iE '\.(cpp|cc|c|h|hpp)$')
do
    echo "checking ${file} ..."
    diff=$(clang-format -output-replacements-xml "${file}" | grep -c "<replacement ")
    if [ "${diff}" -ne 0 ] 
    then
        echo "formatting ${file} ..."
        clang-format -i "${file}"
    else
        echo "${file} is already formatted"
    fi
done

echo "done!"
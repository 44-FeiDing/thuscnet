#!/bin/sh

# This script merge all the .hpp(in the "include/") and .cpp(in the "src/") file to a single .cpp file and delete the lines contain "include "..."" in the output_file.
# Usage: ./merge.sh <output_file>

# Merge all the .hpp and .cpp files into a single file
touch $1
for file in include/*.hpp; do
    echo "Merging $file"
    echo "// $file" >> $1
    cat $file >> $1
    echo "" >> $1
done

for file in src/*.cpp; do
    echo "Merging $file"
    echo "// $file" >> $1
    cat $file >> $1
    echo "" >> $1
done

# Remove the lines contain "include "..."" in the output_file
sed -i '/#include "/d' $1

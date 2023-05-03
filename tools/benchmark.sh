#!/bin/bash

# Create or clear the benchmark_results file
> benchmark_results
> benchmark_results_alternate


#git clone https://github.com/ada-url/url-various-datasets.git

cd url-various-datasets

# Find all text files and pipe them into the adaparse command
find . -type f -name "*.txt" -print0 | while IFS= read -r -d $'\0' file; do
    echo "Processing file: $file"
    echo "$file" >> ../benchmark_results
    cat "$file" | ../../build/tools/adaparse --benchmark | tail -n 3 >> ../benchmark_results
    echo "----------" >> ../benchmark_results

    echo "$file" >> ../benchmark_results_alternate
    cat "$file" | ../../build/tools/adaparse --benchmark --alternate | tail -n 3 >> ../benchmark_results_alternate
    echo "----------" >> ../benchmark_results_alternate
done

# Go back to the original directory
cd ..

echo "All text files processed."

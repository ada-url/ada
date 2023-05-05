#!/bin/bash

# Set the number of trials
num_trials=50

wget https://github.com/ada-url/url-various-datasets/raw/main/top100/top100.txt

# File list to benchmark against
files=("top100.txt") #"linux_files.txt" "wikipedia_100k.txt" 

# Run the programs for the specified number of trials
for file in "${files[@]}"; do
  echo "Benchmarking $file"

  # Variables to store the sum of the Gb/s values for each program
  sum_fastpipespeed=0

  for i in $(seq 1 $num_trials); do
      result_fastspeed=$(cat $file | ../build/tools/adaparse --benchmark 2>&1 | tail -1 | grep -oP '\d+(\.\d+)?') 
      sum_fastpipespeed=$(echo "$sum_fastpipespeed + $result_fastspeed" | bc)
  done

  # Compute the averages
  avg_fastpipespeed=$(echo "scale=7; $sum_fastpipespeed / $num_trials" | bc)

  # Display the results
  echo "------------------------------"
  echo "Finished benchmarking $file"
  echo "Number of trials: $num_trials"
  echo "Average Gb/s for fastpipespeed: $avg_fastpipespeed"

  echo "----------------------------"



  echo ""
done

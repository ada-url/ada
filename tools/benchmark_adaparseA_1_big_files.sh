#!/bin/bash

# Set the number of trials
num_trials=50

# File list to benchmark against
files=("top100.txt") #"linux_files.txt" "wikipedia_100k.txt" 

# Run the programs for the specified number of trials
for file in "${files[@]}"; do
  echo "Benchmarking $file"

  # Variables to store the sum of the Gb/s values for each program
  sum_ohohpipespeed=0

  for i in $(seq 1 $num_trials); do
      result_ohohspeed=$(cat $file | ../build/tools/adaparse --benchmark 2>&1 | tail -1 | grep -oP '\d+(\.\d+)?') 
      sum_ohohpipespeed=$(echo "$sum_ohohpipespeed + $result_ohohspeed" | bc)
  done

  # Compute the averages
  avg_ohohpipespeed=$(echo "scale=7; $sum_ohohpipespeed / $num_trials" | bc)

  # Display the results
  echo "------------------------------"
  echo "Finished benchmarking $file"
  echo "Number of trials: $num_trials"
  echo "Average Gb/s for ohohpipespeed: $avg_ohohpipespeed"

  echo "----------------------------"

  #result_ohohspeed=$(cat $file | ../build/tools/adaparse --benchmark | tail -3)
  #echo "$result_ohohspeed"


  echo ""
done

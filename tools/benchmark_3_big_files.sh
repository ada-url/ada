#!/bin/bash

# Set the number of trials
num_trials=50

# File list to benchmark against
files=("linux_files.txt" "wikipedia_100k.txt" "top100.txt")

# Run the programs for the specified number of trials
for file in "${files[@]}"; do
  echo "Benchmarking $file"

  # Variables to store the sum of the Gb/s values for each program
  sum_ohohpipespeed=0
  sum_pipespeed=0
  sum_cpipespeed=0
  sum_fastpipespeed=0

  for i in $(seq 1 $num_trials); do
      result_ohohspeed=$(cat $file | ../build/tools/adaparse --benchmark | tail -1 | grep -oP '\d+(\.\d+)?') 

      result_pipespeed=$(cat $file | ../build/tools/adaparseD -b | tail -1 | grep -oP '\d+(\.\d+)?') 
      result_cpipespeed=$(cat $file | ../build/tools/adaparseC -b | tail -1 | grep -oP '\d+(\.\d+)?')
      result_fastpipespeed=$(cat $file | ../build/tools/adaparseB -b | tail -1 | grep -oP '\d+(\.\d+)?')

      sum_ohohpipespeed=$(echo "$sum_ohohpipespeed + $result_ohohspeed" | bc)
      sum_pipespeed=$(echo "$sum_pipespeed + $result_pipespeed" | bc)
      sum_cpipespeed=$(echo "$sum_cpipespeed + $result_cpipespeed" | bc)
      sum_fastpipespeed=$(echo "$sum_fastpipespeed + $result_fastpipespeed" | bc)
  done

  # Compute the averages
  avg_ohohpipespeed=$(echo "scale=7; $sum_ohohpipespeed / $num_trials" | bc)
  avg_pipespeed=$(echo "scale=7; $sum_pipespeed / $num_trials" | bc)
  avg_cpipespeed=$(echo "scale=7; $sum_cpipespeed / $num_trials" | bc)
  avg_fastpipespeed=$(echo "scale=7; $sum_fastpipespeed / $num_trials" | bc)

  # Display the results
  echo "------------------------------"
  echo "Finished benchmarking $file"
  echo "Number of trials: $num_trials"
  echo "Average Gb/s for ohohpipespeed: $avg_ohohpipespeed"
  echo "Average Gb/s for pipespeed: $avg_pipespeed"
  echo "Average Gb/s for cpipespeed: $avg_cpipespeed"
  echo "Average Gb/s for fastpipespeed: $avg_fastpipespeed"
  echo ""
done

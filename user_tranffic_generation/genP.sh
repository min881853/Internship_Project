#!/bin/bash

total=0
success=0

trap ctrl_c INT

function ctrl_c() {
  echo ""
  echo "=== Summary ==="
  echo "Total ping attempts: $total"
  echo "Successful responses: $success"
  if [ $total -gt 0 ]; then
    echo "Response rate: $(awk "BEGIN {printf \"%.2f\", ($success/$total)*100}") %"
  else
    echo "Response rate: 0.00 %"
  fi
  exit
}

while true; do
  sleep_time=$(awk -v min=0.2 -v max=0.8 'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}')
  
  if ! [[ "$sleep_time" =~ ^[0-9]*\.[0-9]+$ ]]; then
    echo "Error: Invalid sleep_time value: $sleep_time"
    sleep_time=0.5
  fi

  SIZE=$((RANDOM % 500 + 28)) # 28-527 bytes

  ((total++))
  output=$(ping -s $SIZE -w 1 -c 1 10.0.0.4 2>/dev/null)

  if echo "$output" | grep -q "1 received"; then
    ((success++))
  fi

  sleep "$sleep_time"
done

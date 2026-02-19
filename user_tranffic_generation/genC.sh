## curl 
#!/bin/bash

url="http://10.0.0.4/"
log_file="Userlog.csv"

if [ ! -f "$log_file" ]; then
    echo "Timestamp,HTTP_Code,Delay(s),Status" >> "$log_file"
fi

while true; do
    # Generate random sleep time between 0.2 - 0.8 seconds
    sleep_time=$(awk 'BEGIN { print 0.2 + rand() * 0.6 }')

    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    start_time=$(date +%s%3N)
    http_code=$(curl -o /dev/null -s -w "%{http_code}" --max-time 5 "$url")
    exit_code=$?
    end_time=$(date +%s%3N)
    delay=$(echo "scale=3; ($end_time - $start_time)/1000" | bc)

    if [ "$exit_code" -eq 0 ]; then
        status="OK"
        echo "[$timestamp] Response: $http_code | Delay: ${delay}s"
    else
        status="FAIL"
        echo "[$timestamp] ERROR: $http_code (curl exit $exit_code) | Delay: ${delay}s"
    fi

    echo "$timestamp,$http_code,$delay,$status" >> "$log_file"

    sleep $sleep_time
done

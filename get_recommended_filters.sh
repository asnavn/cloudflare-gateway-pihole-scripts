#!/bin/bash

# create an empty input.csv file
touch input.csv

# declare an array of urls
urls=(
  https://raw.githubusercontent.com/bigdargon/hostsVN/master/option/domain.txt
  https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt
  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
)

# loop through the urls and download each file with curl
for url in "${urls[@]}"; do
  # get the file name from the url
  file=$(basename "$url")
  # download the file with curl and save it as file.txt
  curl -o "$file.txt" "$url"
  # append the file contents to input.csv and add a newline
  cat "$file.txt" >>input.csv
  echo "" >>input.csv
  # remove the file.txt
  rm "$file.txt"
done

# create an empty snalist.csv file
touch snalist.csv

# declare an array of urls2
urls2=(
  https://raw.githubusercontent.com/asnavn/asnavn/main/block-scam-and-ads-link/block-scam-and-ads-link.txt
)

# loop through the urls and download each file with curl
for url in "${urls2[@]}"; do
  # get the file name from the url
  file=$(basename "$url")
  # download the file with curl and save it as file.txt
  curl -o "$snalist.txt" "$url"
  # append the file contents to input.csv and add a newline
  cat "$snalist.txt" >>snalist.csv
  echo "" >>snalist.csv
  # remove the file.txt
  rm "$snalist.txt"
done

# print a message when done
echo "Done. The input.csv file and snalist.csv file contain merged data from recommended filter lists."

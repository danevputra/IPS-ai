import csv

threshold = 1
below = 0
equal = 0
file_name = "sqli.csv"

with open(file_name, newline="\n",encoding='utf-16') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        val = int(row.get("Label", 0))
        if val < threshold:
            below += 1
        elif val == threshold:
            equal += 1

print(f"{below:,} below")
print(f"{equal:,} equal")
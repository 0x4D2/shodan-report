# scripts/run-example.sh (INS GIT)
#!/bin/bash
# Beispiel: Wie man Jobs verarbeitet
echo "KUNDE1 8.8.8.8 2025-01" > jobs-example.txt
echo "KUNDE2 1.1.1.1 2025-01" >> jobs-example.txt

while read -r customer ip month; do
  python -m shodan_report.cli -c "$customer" -i "$ip" -m "$month" --quiet
done < jobs-example.txt

rm jobs-example.txt
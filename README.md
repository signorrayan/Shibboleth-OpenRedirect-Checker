# Shibboleth-OpenRedirect-Checker

### How to use:
- `pip install aiohttp`
- Create a file containing domains (one per line), Then:
```shell
# Basic usage with given filename containing domains
python main.py domains.txt --concurrent 150 --batch-size 500

# Save results with detailed output
python main.py domains.txt -c 150 -b 500 -o vulnerable.txt -do detailed_results.json

# Faster scan (more concurrent connections)
python main.py domains.txt -c 300 -b 1000 -o vulnerable.txt

python3 main.py domains.txt -s
  ```

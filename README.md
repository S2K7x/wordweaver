# WordWeaver v2.0

**A Personalized Wordlist Generator**

## ⚠️ Disclaimer ⚠️

**This tool performs web crawling which can be resource-intensive for both your machine and the target server.** Running this tool against websites without explicit, written permission from the owner may violate terms of service or trigger security alerts. **Use responsibly and ethically.** The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

## Description

WordWeaver is a Python-based tool designed to generate personalized wordlists tailored to a specific web target. It gathers potential keywords from multiple sources including user input, crawling web pages (extracting words from text, comments, and common HTML attributes), and analyzing linked JavaScript files. It then applies various transformations (case changes, affixing common prefixes/suffixes/extensions) and filters the results to create a custom wordlist useful for fuzzing, brute-forcing, or other security testing tasks.

## Features

* **Multiple Word Sources:**
    * Crawls target URLs (configurable depth) to extract words from HTML text, comments, and specified attributes (`alt`, `title`, `placeholder`, etc.).
    * Analyzes discovered JavaScript files to extract potential words (variable names, string literals) using regex.
    * Accepts base keywords from command-line arguments (`-k`) or a file (`-kF`).
* **Transformations:**
    * Case Variations: Generates lowercase, uppercase, and capitalized versions of words.
    * Affixes: Adds common prefixes (`admin_`, `backup_`), suffixes (years, numbers, `.bak`, `.old`), and file extensions.
* **Customization & Control:**
    * Specify target URLs and crawl depth (`-u`, `-d`).
    * Enable/disable specific techniques (`--no-crawl`, `--no-keywords`, `--no-case`, `--no-affix`, `--no-js-extract`, `--no-attr-extract`).
    * Filter final wordlist by minimum and maximum length (`--min-len`, `--max-len`).
    * Control scan speed and load with workers (`-w`), delay (`--delay`), and timeout (`--timeout`).
    * Set custom User-Agent (`--user-agent`) and ignore SSL errors (`-k`).
* **Concurrency:** Uses `ThreadPoolExecutor` for faster crawling and JS analysis.
* **Output:** Prints the unique, sorted wordlist to stdout or saves it to a file (`-o`).
* **Logging:** Configurable logging levels (`-v`, `-q`) and optional logging to file (`--log-file`).

## Requirements

* Python 3.7+
* Python libraries listed in `requirements.txt`:
    * `requests`
    * `beautifulsoup4`
    * `lxml` (Recommended parser for BeautifulSoup, often faster)
    * `urllib3` (Usually installed with requests)

## Installation

1.  **Clone the repository (or download the script):**
    ```bash
    # git clone <your-repo-url>
    # cd wordweaver
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(You might need to install `lxml` separately if it causes issues: `pip install lxml`)*

## Usage

```bash
python wordweaver.py [options]
```

**Input Source Options (At least one source method must be enabled/provided):**

* `-u URL`, `--url URL`: Target URL(s) to crawl. Can use multiple times. (Required if not using `--no-crawl`).
* `-k KEYWORD`, `--keyword KEYWORD`: Base keyword(s). Can use multiple times.
* `-kF FILE`, `--keyword-file FILE`: File containing base keywords (one per line).

**Output Options:**

* `-o FILE`, `--output-file FILE`: File to save the generated wordlist. (Default: print to stdout).
* `--min-len LEN`: Minimum length of words to include (Default: 3).
* `--max-len LEN`: Maximum length of words to include (Default: 25).

**Technique Selection (Default: All Enabled):**

* `--no-crawl`: Disable crawling target URLs.
* `--no-keywords`: Disable using provided keywords (CLI/File).
* `--no-case`: Disable case transformations.
* `--no-affix`: Disable adding prefixes/suffixes/extensions.
* `--no-js-extract`: Disable extracting words from JavaScript files.
* `--no-attr-extract`: Disable extracting words from HTML attributes.

**Scan Control Options:**

* `-d DEPTH`, `--depth DEPTH`: Maximum crawl depth (Default: 1).
* `-w WORKERS`, `--workers WORKERS`: Number of concurrent workers (Default: 15).
* `--delay DELAY`: Delay between requests per worker (seconds, Default: 0).
* `--timeout TIMEOUT`: Request timeout (seconds, Default: 10).
* `--user-agent UA`: Custom User-Agent string.
* `-k`, `--insecure`: Ignore SSL certificate errors during crawl.

**Logging Options:**

* `--log-file FILE`: File to write detailed logs to.
* `-v`, `--verbose`: Enable debug logging.
* `-q`, `--quiet`: Suppress info messages (show warnings/errors only).

**Examples:**

1.  **Crawl a site (depth 1) and use keywords from a file, save to output:**
    ```bash
    python wordweaver.py -u [https://example.com](https://example.com) -kF keywords.txt -o wordlist.txt
    ```

2.  **Use only CLI keywords, apply all transformations, filter length:**
    ```bash
    python wordweaver.py -k admin -k backup -k test --no-crawl --min-len 4 --max-len 10
    ```

3.  **Deep crawl, disable affix generation, verbose logging:**
    ```bash
    python wordweaver.py -u [https://complex-app.com](https://complex-app.com) -d 2 --no-affix -v --log-file crawl.log
    ```

4.  **Crawl, but disable JS and Attribute extraction:**
    ```bash
    python wordweaver.py -u [https://example.com](https://example.com) --no-js-extract --no-attr-extract
    ```

## Output Interpretation

* The tool outputs a list of unique words, one per line, sorted alphabetically.
* These words are derived from the enabled input sources (crawl, keywords) and processed through the enabled transformations (case, affixes) and filters (length).
* Check the log output (console or file) for details on the process, including discovered URLs, JS files, and word counts at different stages.

## Limitations

* **Word Extraction:** Relies on regular expressions, which may miss some words or extract non-relevant strings (especially from JS). It doesn't understand natural language.
* **Crawler:** Basic BFS crawler; doesn't handle JavaScript-rendered content/links, complex redirects, or obey `robots.txt` strictly. Crawl depth handling with concurrency is functional but could be further optimized.
* **Transformations:** Affix and case transformations are basic; doesn't include more complex mutations or pattern generation.
* **Performance:** Crawling and analysis can be slow on large websites or with high worker counts/low delays.

## License

(Specify your chosen license here, e.g., MIT License)

```
[Link to LICENSE file or full license text]
```

## Contributing

(Optional: Add guidelines if you want others to contribute)

```
Contributions are welcome! Please read CONTRIBUTING.md for details.

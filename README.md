# Summary
A log parser, threat detector, and llm analyzer and daily report generator. It is setup to use Auditd, Auth, UFW, and WAF logs. As of now because of hardware limitations this is more a proof of concept than something that could be used at scale. It would be easy to configure the config.py and llm_analyze.py scripts to use a better model for processing and could then be used for larger servers.

# The Full Daily Pipeline is Four Steps:

### 1. Parse Logs
`python3 LogProcessing/auditd-log-parser.py; python3 LogProcessing/auth-log-parser.py; python3 LogProcessing/safeline-log-parser.py; python3 LogProcessing/ufw-log-parser.py`

### 2. detect + correlate + write the raw report
`python3 ioc_hunter/main.py --auth ... --auditd ... --ufw ... --waf ... --outdir ioc_output --db actors.db`
the --auth, --auditd, --ufw, and --waf paths can be set in config.py and can be left out of the cli

### 3. split into LLM-sized, signal-routed chunks (compact text by default)
`python3 ioc_hunter/chunk_report.py ioc_output/[yyyy-mm-dd]/ioc_report_2026-07-09.json`

### 4. analyze with the local model and write the daily report
`python3 llm_analyze.py ioc_output/[yyyy-mm-dd]/chunks --out ioc_output/[yyyy-mm-dd]/daily_report.md`

# Overview of the Process

---------------------
|       Logs        |
---------------------
          ↓
step 1
---------------------
|      Parsers      |
|         ↓         |
|    jsonl files    |
---------------------
          ↓
step 2
---------------------
|      main.py      |
| ----------------- |
|   ioc detectors   |
|         ↓         |
|  ioc_report.json  |
---------------------
          ↓
step 3
---------------------
|  chunk_report.py  |
|         ↓         |
|    chunk files    |
|  low level table  |
---------------------
          ↓
step 4
---------------------
|  llm_analyze.py   |
|         ↓         |
|   daily report    |
---------------------

### Parsing
Currently there are four parsing scripts, one for each log file. These use regex (besides ufw) to extract pertinent info and then save it as josnl files for log processing.

In the future this will be consolidated to one script that handles all four log files, instead of running one script for each log.

### Main.py
Loads the four jsonl files, runs a detector for each log type, looks up identified actors in the actor.db, updates the actor.db with new actors, takes each flagged actor and searches all log events to correlate activity, and writes the ioc_report_YYYY-MM-DD.json file. 

### Chunking
chunk_report.py splits events into high-level and low-level (failed attempts, scanners, events that didn't actually compromise the system) and transforms data from json to compact text (to simply for the llm and lower the token burden). The high-level events are sorted and chunked by actor, so that each chunk file is only for one actor. This is so each file is a self-contained record of events that the llm can process without losing context. 

There is a lot of work happening here to compact and cut low-level data to fit the small context window of the llm, which is running on CPU only due to hardware constraints (read: GPUs cost a lot of money)

### LLM Analysis
A local Ollama-served model is called once per chunk file and then one final time to synthesize the report. There is a built-in guard that validates every IOC the model cites against the chunk file (invented ips are dropped and logged). It is also given strict instructions against inventing attributions to threat-actors, malware, or CVEs.

# Notes on Local LLM Hosting
One of the big considerations I had for choosing to locally host an LLM was data privacy. It would have been possible to rent GPUs through a service like vast.ai (and I really considered it).

I used a VPS with 8 cores of CPU and 32GB of RAM, because it was the best I could afford at the time.

I decided I would rather this be a good proof of concept built on a zero trust framework that could be taken to the next level with better suited hardware in the future. This seemed more realistic and also provided good experience of having to balance performance, security, and budget.

# Future Upgrades:
- Add machine info to all log entries, with the idea of pulling logs from multiple servers and endpoints.
- Run everything from one script instead of, at the time of writing this, running 7 scripts
- Upgrade hardware to run a model capable of better reasoning and larger context.
- Pulling threat intelligence daily to enhance detection.
# Algorithms & Pseudocode

## 9.1 Core Scan Orchestration Algorithm

### Context (Code Mapping)

- Implemented in: `modules/scanner.py`
- Main class: `VulnerabilityScanner`
- Main method: `run_all_scans(options=None)`

### Purpose

- Validate input URL
- Run multiple vulnerability checks concurrently
- Aggregate results
- Compute a summary and risk level

### Pseudocode: `run_all_scans(options)`

```text
ALGORITHM RunAllScans(url, options)
INPUT: target url, scan options
OUTPUT: aggregated scan results

1. IF options is NULL THEN
2.    options <- enable all scan modules
3. ENDIF

4. Initialize results dict with empty lists per scan type
5. Create ThreadPoolExecutor with max_workers
6. FOR each scan type in options
7.    IF options[scan type] is enabled
8.        submit corresponding scan task to executor
9.        store future -> scan_type mapping
10.   ENDIF
11. ENDFOR

12. FOR each future as it completes
13.    scan_type <- mapping[future]
14.    TRY
15.        scan_result <- future.result(timeout)
16.        results[scan_type] <- scan_result
17.        results.summary[scan_type] <- count(scan_result)
18.    CATCH exception
19.        results[scan_type] <- empty
20.        results.summary[scan_type] <- 0
21.    ENDTRY
22. ENDFOR

23. total_vulns <- sum(summary values)
24. risk_level <- compute based on total_vulns thresholds
25. results.summary.total_vulnerabilities <- total_vulns
26. results.summary.risk_level <- risk_level

27. RETURN results
END
```

## 9.2 URL Validation Algorithm

### Context (Code Mapping)

- Implemented in: `utils/validator.py`
- Used by: `modules/scanner.py`, `app.py`

### Goal

Reject malformed URLs early to reduce scan errors.

### Pseudocode

```text
ALGORITHM ValidateURL(url)
1. IF url is empty THEN return False
2. Parse url using URL parser
3. IF scheme not in {http, https} THEN return False
4. IF netloc/domain is empty THEN return False
5. return True
```

## 9.3 Web Crawling Algorithm (Attack Surface Mapping)

### Context (Code Mapping)

- Implemented in: `web_scraper.py` (`crawl_website`)

### Pseudocode (BFS-style crawl)

```text
ALGORITHM CrawlWebsite(base_url, max_depth, max_pages)
OUTPUT: dictionary of crawled pages and metadata

1. queue <- [(base_url, 0)]
2. visited <- empty set
3. results <- empty dict
4. page_count <- 0

5. WHILE queue not empty AND page_count < max_pages
6.    (current_url, depth) <- pop front queue
7.    IF current_url in visited THEN continue
8.    visited.add(current_url)

9.    response <- HTTP GET current_url
10.   text_content <- extract clean text
11.   results[current_url] <- {depth, status, title, text_content}
12.   page_count <- page_count + 1

13.   IF depth < max_depth THEN
14.       links <- extract internal links from HTML
15.       FOR each link in links
16.           IF link not in visited THEN
17.               queue.push((link, depth+1))
18.           ENDIF
19.       ENDFOR
20.   ENDIF
21. ENDWHILE

22. RETURN results
```

## 9.4 AI-Assisted Security Analysis Algorithm

### Context (Code Mapping)

- `wolf_api.py`: `WolfAPI.analyze_security(text, analysis_type, context)`
- `security_analyzer.py`: prompt construction for website analysis, threat detection, and web app scan simulation.

### Pseudocode

```text
ALGORITHM AnalyzeWithAI(input_text, analysis_type, context)
1. IF demo_mode = True OR api_key missing THEN
2.    return simulated_demo_response(analysis_type)
3. ENDIF

4. system_prompt <- select security prompt by analysis_type
5. full_prompt <- system_prompt + context + input_text + JSON output instructions
6. response <- LLM.generate_content(full_prompt)
7. json <- attempt to parse JSON from response
8. IF parse succeeds THEN return json
9. ELSE return structured fallback result
```

## 9.5 Report Generation Algorithm

### Context (Code Mapping)

- `report_generator.py`: `ReportGenerator.generate_reports()`

### Pseudocode

```text
ALGORITHM GenerateHTMLReport(results)
1. score <- calculate_security_score(results)
2. issues <- flatten results into issue list grouped by scan_type
3. charts <- generate visualizations (gauge, pie, bars, heatmap)
4. watermark <- generate watermark image
5. render HTML template with report_data
6. return HTML
```

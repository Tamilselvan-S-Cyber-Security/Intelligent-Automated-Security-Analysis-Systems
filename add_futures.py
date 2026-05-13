import sys
import re

def add_futures_to_wolf():
    # Read the fixed file
    with open('wolf_fixed.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Add concurrent.futures import if not already present
    if 'import concurrent.futures' not in content:
        content = content.replace(
            'import asyncio',
            'import asyncio\nimport concurrent.futures'
        )
    
    # Find and modify the website analysis function to use futures
    # This pattern looks for the website analysis function with concurrent.futures
    pattern = r'(with concurrent\.futures\.ThreadPoolExecutor\(\) as executor:.*?progress_bar\.progress\(\(i \+ 1\) \* 100 // len\(futures\)\))'
    
    # If the pattern is found, the futures code is already there
    if re.search(pattern, content, re.DOTALL):
        print("Futures functionality already exists in the code.")
    else:
        # Look for a simpler pattern to find where to add the futures code
        simple_pattern = r'(progress_bar = st\.progress\(0\).*?results = \[\])'
        
        # Replacement with futures implementation
        replacement = r'\1\n\n                            with concurrent.futures.ThreadPoolExecutor() as executor:\n                                futures = [executor.submit(api_client.analyze_website, url, scan_type=scan) \n                                         for scan in scan_options]\n                                \n                                for i, future in enumerate(concurrent.futures.as_completed(futures)):\n                                    results.append(future.result())\n                                    progress_bar.progress((i + 1) * 100 // len(futures))'
        
        # Replace the pattern with the futures implementation
        modified_content = re.sub(simple_pattern, replacement, content, flags=re.DOTALL)
        
        # If the content was modified, write it back to the file
        if modified_content != content:
            with open('wolf_fixed.py', 'w', encoding='utf-8') as f:
                f.write(modified_content)
            print("Successfully added futures functionality to wolf_fixed.py")
        else:
            print("Could not find the pattern to replace. Manual modification may be required.")

if __name__ == "__main__":
    add_futures_to_wolf()

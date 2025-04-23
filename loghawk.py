import re
import json
import argparse
import os
from collections import defaultdict


def parse_args():
    '''
    Parses command-line arguments for the LogHawk log monitoring tool.

    Returns:
        An object containing the parsed arguments:
            - log (str): Path to the log file to analyze.
            - config (str): Path to the configuration file.
    '''
    parser = argparse.ArgumentParser(description="LogHawk - Log Monitoring Tool")

    # Required positional argument (log file path)
    parser.add_argument("log", help="Path to the log file to anaylze.")

    # Required named argument (config file path)
    parser.add_argument("--config", required=True, help="Path to the config file.")

    return parser.parse_args()


def load_config(config_path):
    '''
    Opens and reads the JSON configuration file containing log scanning threats.

    Parameters:
        config_path (str): Path to the JSON config file.

    Returns:
        dict: A dictionary mapping log file names to their associated detection threats.

    Raises:
        FileNotFoundError: If the config file does not exist.
    '''
    try:
        with open(config_path, 'r') as config_file:
            return json.load(config_file)
    except FileNotFoundError:
        print(f"[ERROR] Config not found: {config_path}")
        return []
    except Exception as e:
        print(f"[ERROR] Failed to read config file: {e}")
        return []
    
    
def load_log(log_path):
    """
    Opens and reads the specified log file.

    Args:
        log_path (str): The path to the log file.

    Returns:
        list[str]: A list of lines from the log file.

    Raises:
        FileNotFoundError: If the log file does not exist.
    """
    try:
        with open(log_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {log_path}")
        return []
    except Exception as e:
        print(f"[ERROR] Failed to read log file: {e}")
        return []



def scan_log(log_file_name, log_file, config_file):
    """
    Scans the provided log lines for security threats defined in the config file.

    Parameters:
    - log_file_name (str): The name of the log file being analyzed (e.g., "auth.log").
    - log_file (list): A list of strings, each representing a line from the log file.
    - config_file (dict): Configuration dictionary containing threat definitions, 
                          regex patterns, and optional thresholds for each log type.

    The function dynamically handles:
    - Count-based threats (e.g., brute-force attacks, which require repeated pattern matches to trigger an alert).
    - Match-based threats (e.g., a single log line matching a pattern is enough to raise an alert).
    """

    # Get the list of threats defined for this specific log file
    threats = config_file.get(log_file_name)

    # If no threats are defined for this log type, skip scanning
    if not threats:
        print(f"No threats defined for {log_file_name} in config.")
        return

    # Iterate through each threat defined in the config for this log file
    for threat in threats:
        threat_name = threat["threat"]
        threat_pattern_str = threat["pattern"]
        threshold = 0  
        group_by = ''

        # Attempt to load the threshold value (if it's a count-based threat)
        try:
            threshold = threat["threshold"]
            group_by = threat["group_by"]
        except KeyError:
            pass  # If no threshold is defined, it's treated as a match-based threat

        # Compile the regex pattern for performance
        pattern = re.compile(threat_pattern_str)

        # Handle count-based threats (e.g., brute-force detection)
        if threshold:
            # Count the number of times each grouped value (e.g., IP, endpoint, username) appears
            grouped_value_count = defaultdict(int)

            # Store evidence grouped by the specified field and corresponding line numbers
            evidence_list = defaultdict(dict)

            # Iterate through each log line and apply the regex pattern
            for line_number, line in enumerate(log_file, start=1):
                match = pattern.search(line)
                if match:
                    # Extract the dynamic group key (e.g., IP, endpoint, etc.) from the regex match
                    group_value = match.groupdict().get(group_by)

                    # Increment the count for this group value
                    grouped_value_count[group_value] += 1

                    # Store the line as evidence under the corresponding group value and line number
                    evidence_list[group_value][line_number] = line.strip()

            # After scanning all lines, check which group values exceeded the defined threshold
            for value, occurrences in grouped_value_count.items():
                if occurrences >= threshold:
                    # Display alert and all matching log lines for that group value
                    print("=" * 60)
                    print(f"[ALERT] {threat_name}")
                    print(f"Log File     : {log_file_name}")
                    print(f"Suspect      : {value}")
                    print(f"Occurrences  : {occurrences} (Threshold: {threshold})")
                    print("-" * 60)

                    for line_number, evidence in evidence_list[value].items():
                        print(f"Line {line_number}: {evidence}")

                    print("=" * 60 + "\n")


        else:
            # For match-based threats, collect all lines that match the pattern
            evidence_list = {}

            for line_number, line in enumerate(log_file, start=1):
                if pattern.search(line):
                    # Store the matched line along with its line number
                    evidence_list[line_number] = line.strip()

            # Display alert and all matching log lines
            print("=" * 50)
            print(f"[ALERT] {threat_name}")
            print(f"Log File: {log_file_name}")
            print(f"Matches Found: {len(evidence_list)}")
            print("-" * 50)

            for line_number, evidence in evidence_list.items():
                print(f"Line {line_number}: {evidence}")

            print("=" * 50 + "\n\n")



def main():
    # Command Usage: python loghawk.py <path-to-file> --config <path-to-config>
    args = parse_args()
    
    LOG_FILE_PATH = args.log
    CONFIG_FILE_PATH = args.config

    # Open log file
    log_name = os.path.basename(LOG_FILE_PATH)
    log = load_log(LOG_FILE_PATH)

    # Open config.json file
    config = load_config(CONFIG_FILE_PATH)

    # Scan the log file
    scan_log(log_name, log, config)
  


if __name__ == '__main__':
    main()


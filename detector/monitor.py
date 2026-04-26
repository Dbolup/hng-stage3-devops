import time
import os


def tail_log(filepath):
    """
    Continuously tail a log file line by line.
    Waits for the file to exist, then follows it like 'tail -f'.
    Yields each new line as it appears.
    """
    # Wait until log file exists
    while not os.path.exists(filepath):
        print(f"[monitor] Waiting for log file: {filepath}")
        time.sleep(2)

    with open(filepath, "r") as f:
        # Move to end of file so we only read NEW lines
        f.seek(0, 2)
        print(f"[monitor] Now tailing: {filepath}")

        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)

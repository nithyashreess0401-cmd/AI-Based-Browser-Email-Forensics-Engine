import subprocess
import sys

print("======================================")
print("     EMAIL FORENSICS ANALYSIS")
print("======================================\n")

scripts = [
    "header_analysis.py",
    "metadata.py",
    "url_extractor.py",
    "authentication.py",
    "link_detector.py",
    "report_generator.py"
]

for script in scripts:
    print(f"\n>>> Running {script}...\n")

    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True
    )

    print(result.stdout)

    if result.returncode != 0:
        print(f"ERROR in {script}:")
        print(result.stderr)
        break

print("\n======================================")
print("     EMAIL FORENSICS COMPLETED")
print("======================================")
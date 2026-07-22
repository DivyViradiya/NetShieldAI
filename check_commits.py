import subprocess

def run(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

with open("git_info.txt", "w", encoding="utf-8") as f:
    f.write("=== Git Log ===\n")
    f.write(run("git log --oneline -n 10"))
    
    f.write("\n\n=== Files in Latest Commit (HEAD) ===\n")
    f.write(run("git show --name-only --oneline HEAD"))
    
    f.write("\n\n=== Staged Files ===\n")
    f.write(run("git diff --cached --name-only"))
    
    f.write("\n\n=== Search for Large File in Commits ===\n")
    # Search for files added that match .results/
    f.write(run("git log --name-only --all -- *upload_temp_AirImprovement.zip"))

from fastapi import FastAPI
app = FastAPI(title="File Analyzer - Scaffold")
@app.get("/health")
def health():
    return {"service": "file-analyzer", "status": "ok", "implementation": "scaffold"}
# No analysis endpoints yet: never mark files safe without actual scans.

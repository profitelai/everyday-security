"""Turn the HTML report into a PDF with a headless browser that is already installed (Chrome, Chromium, Edge or Brave).
The engine itself stays standard-library only; no browser means no PDF, and the HTML report can always be printed to PDF by hand."""
import os, shutil, subprocess, tempfile

CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser",
]


def find_browser(env=os.environ):
    forced = env.get("EVERYDAY_BROWSER")
    if forced: return forced if os.path.exists(forced) or shutil.which(forced) else None
    for c in CANDIDATES:
        p = c if os.path.isabs(c) and os.path.exists(c) else shutil.which(c)
        if p: return p
    return None


def html_to_pdf(html_path, pdf_path, browser=None, timeout=90):
    """Return pdf_path, or None when no browser is available or it failed."""
    browser = browser or find_browser()
    if not browser: return None
    with tempfile.TemporaryDirectory() as profile:           # separate profile so a running browser is never touched
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run", f"--user-data-dir={profile}", "--no-pdf-header-footer",
               f"--print-to-pdf={os.path.abspath(pdf_path)}", "file://" + os.path.abspath(html_path)]
        try: subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired): return None
    return pdf_path if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 1000 else None

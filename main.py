from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import re
import whois
import validators
import httpx

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")  


def is_suspicious(url: str) -> dict:
    result = {
        "valid": validators.url(url),
        "suspicious_patterns": False,
        "recent_domain": False,
        "private_owner": False,
        "redirect_chain": []
    }

    if not result["valid"]:
        return result  

    # Heurísticas
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url) or url.count(".") > 3:
        result["suspicious_patterns"] = True

    # Whois
    try:
        domain_info = whois.whois(url)
        if domain_info.creation_date:
            from datetime import datetime, timedelta
            age = datetime.now() - domain_info.creation_date
            if isinstance(age, list):
                age = datetime.now() - age[0]
            result["recent_domain"] = age < timedelta(days=180)
        if "Withheld" in str(domain_info):
            result["private_owner"] = True
    except Exception:
        result["whois_error"] = True
 
    # Redirecionamentos
    try:
        with httpx.Client(follow_redirects=True, timeout=10) as client:
            r = client.get(url)
            result["redirect_chain"] = [str(resp.url) for resp in r.history] + [str(r.url)]
    except Exception:
        result["redirect_error"] = True

    return result


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/check_url")
async def check_url(url: str = Form(...)):
    result = is_suspicious(url)
    return JSONResponse(content=result)


# deploying
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)   
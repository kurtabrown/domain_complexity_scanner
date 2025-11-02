from playwright.sync_api import sync_playwright
import httpx

def host(u):
    try: return httpx.URL(u).host
    except: return None

with sync_playwright() as p:
    # Force H1 to dodge ERR_HTTP2_PROTOCOL_ERROR
    browser = p.chromium.launch(
        headless=True,
        args=["--disable-http2","--no-sandbox","--disable-gpu","--disable-blink-features=AutomationControlled"]
    )
    ctx = browser.new_context(ignore_https_errors=True,
                              user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                                          "Chrome/120.0.0.0 Safari/537.36"))
    ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
    page = ctx.new_page()
    urls = ["https://wellesleyfarms.com/","https://www.wellesleyfarms.com/","http://wellesleyfarms.com/","http://www.wellesleyfarms.com/"]
    for u in urls:
        try:
            # Use a lighter wait condition to avoid hanging
            page.goto(u, wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(2000)
            print(u, "=>", page.url, "host:", host(page.url))
        except Exception as e:
            # Retry once with an even lighter wait
            try:
                page.goto(u, wait_until="commit", timeout=20000)
                page.wait_for_timeout(2000)
                print(u, "=>", page.url, "host:", host(page.url), "(commit)")
            except Exception as e2:
                print(u, "ERR", e2)
    browser.close()

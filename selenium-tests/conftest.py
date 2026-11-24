import os

import pytest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

BASE_URL = os.environ.get("BASE_URL", "http://localhost:3000").rstrip("/")
SHOTS = os.environ.get("SCREENSHOT_DIR", "screenshots")

ANALYST = ("analyst@packetguard.local", "Analyst123")
ADMIN = ("admin@packetguard.local", "Admin123")


def wait(driver, seconds=20):
    return WebDriverWait(driver, seconds)


@pytest.fixture()
def driver():
    opts = Options()
    for arg in ("--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
                "--disable-gpu", "--window-size=1400,1000"):
        opts.add_argument(arg)
    if os.environ.get("CHROME_BIN"):
        opts.binary_location = os.environ["CHROME_BIN"]
    service = Service(os.environ["CHROMEDRIVER"]) if os.environ.get("CHROMEDRIVER") else Service()
    drv = webdriver.Chrome(service=service, options=opts)
    drv.implicitly_wait(0)
    yield drv
    drv.quit()


def login(driver, email, password):
    driver.get(f"{BASE_URL}/login")
    wait(driver).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "input[type=email]"))).send_keys(email)
    driver.find_element(By.CSS_SELECTOR, "input[type=password]").send_keys(password)
    driver.find_element(By.CSS_SELECTOR, "button.primary").click()


@pytest.fixture()
def analyst(driver):
    login(driver, *ANALYST)
    wait(driver).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "aside.rail")))
    return driver


@pytest.fixture()
def admin(driver):
    login(driver, *ADMIN)
    wait(driver).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "aside.rail")))
    return driver


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        drv = item.funcargs.get("driver")
        if drv is not None:
            os.makedirs(SHOTS, exist_ok=True)
            drv.save_screenshot(os.path.join(SHOTS, f"{item.name}.png"))
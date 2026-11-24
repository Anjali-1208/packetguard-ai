from conftest import ADMIN, ANALYST, BASE_URL, login, wait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC


def body_text(driver):
    return driver.find_element(By.TAG_NAME, "body").text


def alert_rows(driver):
    return driver.find_elements(By.CSS_SELECTOR, "table tbody tr")


def test_login_page_shows_form(driver):
    driver.get(f"{BASE_URL}/login")
    heading = wait(driver).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "form.login-form h2")))
    assert heading.text == "Sign out"
    assert driver.find_element(By.CSS_SELECTOR, "input[type=email]").is_displayed()
    assert driver.find_element(By.CSS_SELECTOR, "input[type=password]").is_displayed()
    assert "PacketGuard" in driver.find_element(By.CSS_SELECTOR, ".login-hero h1").text


def test_unauthenticated_user_is_sent_to_login(driver):
    driver.get(f"{BASE_URL}/alerts")
    wait(driver).until(EC.url_contains("/login"))


def test_wrong_password_shows_error(driver):
    login(driver, ANALYST[0], "WrongPass999")
    error = wait(driver).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "div.err[role=alert]")))
    assert error.text.strip() != ""
    assert "/login" in driver.current_url


def test_analyst_login_opens_dashboard(analyst):
    nav = analyst.find_element(By.CSS_SELECTOR, "aside.rail nav").text
    for item in ("Dashboard", "Live Alerts", "Block Rules", "Notifications"):
        assert item in nav
    assert "Administration" not in nav          # analysts must not see the admin menu
    wait(analyst, 30).until(lambda d: "live stream connected" in body_text(d))


def test_alerts_page_lists_alerts(analyst):
    analyst.get(f"{BASE_URL}/alerts?sort=recent")
    wait(analyst, 120).until(lambda d: len(alert_rows(d)) > 0)
    assert "recommendations" in body_text(analyst)


def test_alert_detail_shows_shap_and_notice(analyst):
    analyst.get(f"{BASE_URL}/alerts?sort=recent")
    wait(analyst, 120).until(lambda d: len(alert_rows(d)) > 0)
    alert_rows(analyst)[0].find_element(By.CSS_SELECTOR, "a").click()
    wait(analyst).until(EC.visibility_of_element_located((By.XPATH, "//h3[text()='Why was this flagged?']")))
    text = body_text(analyst)
    assert "Supervised confidence" in text
    assert "recommendations" in text
    assert "Acknowledge" in text


def test_acknowledge_then_approve_block(analyst):
    analyst.get(f"{BASE_URL}/alerts?status=new&sort=recent")
    wait(analyst, 120).until(lambda d: len(alert_rows(d)) > 0)
    alert_rows(analyst)[0].find_element(By.CSS_SELECTOR, "a").click()
    wait(analyst).until(EC.visibility_of_element_located((By.XPATH, "//h3[text()='Analyst response']")))
    ip = analyst.find_element(By.CSS_SELECTOR, "p.sub.mono").text.split(" ")[0].split(":")[0]

    # the block button must stay disabled until the alert is acknowledged
    block_btn = analyst.find_element(By.XPATH, "//button[normalize-space()='Approve IP block']")
    assert not block_btn.is_enabled()

    analyst.find_element(By.XPATH, "//button[normalize-space()='Acknowledge']").click()
    wait(analyst).until(EC.text_to_be_present_in_element((By.CSS_SELECTOR, "header.page-h span.st"), "Acknowledged"))

    analyst.find_element(By.CSS_SELECTOR, "textarea").send_keys("Selenium test: confirmed malicious source")
    wait(analyst).until(EC.element_to_be_clickable((By.XPATH, "//button[normalize-space()='Approve IP block']"))).click()
    wait(analyst).until(EC.text_to_be_present_in_element((By.CSS_SELECTOR, "header.page-h span.st"), "Blocked"))

    analyst.get(f"{BASE_URL}/blockrules")
    wait(analyst).until(lambda d: ip in body_text(d))


def test_admin_can_open_administration(admin):
    nav = admin.find_element(By.CSS_SELECTOR, "aside.rail nav")
    nav.find_element(By.LINK_TEXT, "Administration").click()
    wait(admin).until(EC.visibility_of_element_located((By.XPATH, "//h1[text()='Administration']")))
    admin.find_element(By.LINK_TEXT, "Detection thresholds").click()
    wait(admin).until(EC.url_contains("/admin/config"))
    admin.find_element(By.LINK_TEXT, "Audit log").click()
    wait(admin).until(EC.url_contains("/admin/audit"))


def test_analyst_cannot_open_admin_area(analyst):
    analyst.get(f"{BASE_URL}/admin/users")
    wait(analyst).until(lambda d: "/admin" not in d.current_url)
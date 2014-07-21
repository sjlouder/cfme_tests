"""Provides functions to login as any user

Also provides a convenience function for logging in as admin using
the credentials in the cfme yamls.

:var page: A :py:class:`cfme.web_ui.Region` holding locators on the login page
"""

from selenium.webdriver.common.keys import Keys

import cfme.fixtures.pytest_selenium as sel
import cfme.web_ui.flash as flash
from cfme import dashboard
from cfme.web_ui import Region, Form, fill
from selenium.common.exceptions import NoSuchElementException, ElementNotVisibleException
from utils import conf
from utils.log import logger
from threading import local
from utils.pretty import Pretty

thread_locals = local()
thread_locals.current_user = None


class User(Pretty):
    pretty_attrs = ['usrename', 'full_name', 'password']

    def __init__(self, username=None, password=None, full_name=None):
        self.full_name = full_name
        self.password = password
        self.username = username


page = Region(
    title="Dashboard",
    locators={
        'username': '//input[@id="user_name"]',
        'password': '//input[@id="user_password"]',
        'submit_button': '//a[@id="login"]',
        # Login page has an abnormal flash div
        'flash': '//div[@id="flash_div"]',
        'logout': '//a[contains(@href, "/logout")]',
        'update_password': '//a[@title="Update Password"]',
        'back': '//a[@title="Back"]',
        'user_new_password': '//input[@id="user_new_password"]',
        'user_verify_password': '//input[@id="user_verify_password"]'
    },
    identifying_loc='submit_button')

_form_fields = ('username', 'password', 'user_new_password', 'user_verify_password')
form = Form(
    fields=[
        loc for loc
        in page.locators.items()
        if loc[0] in _form_fields],
    identifying_loc='username')


def _click_on_login():
    """
    Convenience internal function to click the login locator submit button.
    """
    sel.click(page.submit_button)


def logged_in():
    return sel.is_displayed(dashboard.page.user_dropdown)


def press_enter_after_password():
    """
    Convenience function to send a carriange return at the end of the password field.
    """
    sel.send_keys(page.password, Keys.RETURN)


def login(username, password, submit_method=_click_on_login):
    """
    Login to CFME with the given username and password.
    Optionally, submit_method can be press_enter_after_password
    to use the enter key to login, rather than clicking the button.

    Args:
        user: The username to fill in the username field.
        password: The password to fill in the password field.
        submit_method: A function to call after the username and password have been input.

    Raises:
        RuntimeError: If the login fails, ie. if a flash message appears
    """
    if not logged_in() or username is not current_username():
        if logged_in():
            logout()
        # workaround for strange bug where we are logged out
        # as soon as we click something on the dashboard
        sel.sleep(1.0)

        logger.debug('Logging in as user %s' % username)
        fill(form, {'username': username, 'password': password})
        submit_method()
        flash.assert_no_errors()
        thread_locals.current_user = User(username, password, _full_name())


def login_admin(**kwargs):
    """
    Convenience function to log into CFME using the admin credentials from the yamls.

    Args:
        kwargs: A dict of keyword arguments to supply to the :py:meth:`login` method.
    """
    if current_full_name() != 'Administrator':
        logout()

        username = conf.credentials['default']['username']
        password = conf.credentials['default']['password']
        login(username, password, **kwargs)


def logout():
    """
    Logs out of CFME.
    """
    if logged_in():
        if not sel.is_displayed(page.logout):
            sel.click(dashboard.page.user_dropdown)
        sel.click(page.logout, wait_ajax=False)
        sel.handle_alert(wait=False)
        thread_locals.current_user = None


def _full_name():
    return sel.text(dashboard.page.user_dropdown).split('|')[0].strip()


def current_full_name():
    """ Returns the current username.

    Returns: the current username.
    """
    if logged_in():
        return _full_name()
    else:
        return None


def current_user():
    return thread_locals.current_user


def current_username():
    u = current_user()
    return u and u.username


def fill_login_fields(username, password):
    """ Fills in login information without submitting the form """
    if logged_in():
        logout()
    fill(form, {"username": username, "password": password})


def show_password_update_form():
    """ Shows the password update form """
    if logged_in():
        logout()
    try:
        sel.click(page.update_password)
    except ElementNotVisibleException:
        # Already on password change form
        pass


def update_password(username, password, new_password,
                    verify_password=None, submit_method=_click_on_login):
    """ Changes user password """
    if logged_in():
        logout()
    show_password_update_form()
    fill(form, {
        "username": username,
        "password": password,
        "user_new_password": new_password,
        "user_verify_password": verify_password if verify_password is not None else new_password
    })
    submit_method()


def close_password_update_form():
    """ Goes back to main login form on login page """
    try:
        sel.click(page.back)
    except (ElementNotVisibleException, NoSuchElementException):
        # Already on main login form or not on login page at all
        pass


def clear_fields():
    """ clears all form fields """
    fill(form, {
        "username": "",
        "password": "",
        "user_new_password": "",
        "user_verify_password": ""
    })

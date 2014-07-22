# -*- coding: utf-8 -*-
import pytest
import cfme.configure.access_control as ac
import utils.providers as provider_utils
from utils.update import update
import utils.error as error
import utils.randomness as random
import cfme.fixtures.pytest_selenium as sel
import cfme.infrastructure.virtual_machines as vms
from cfme import Credential
from cfme import login
from cfme.web_ui.menu import nav
from cfme.configure import tasks
from utils import version

usergrp = ac.Group(description='EvmGroup-user')


# due to pytest.mark.bugzilla(1035399), non admin users can't login
# with no providers added
#pytestmark = [pytest.mark.usefixtures("setup_cloud_providers(False)")]
# How to run setup_cloud_providers with argument ^^
@pytest.fixture(scope='function')
def provider_setup():
    provider_utils.setup_cloud_providers(False)


def new_credential():
    return Credential(principal='uid' + random.generate_random_string(), secret='redhat')


def new_user(group=usergrp):
    return ac.User(name='user' + random.generate_random_string(),
                   credential=new_credential(),
                   email='xyz@redhat.com',
                   group=group,
                   cost_center='Workload',
                   value_assign='Database')


def new_group(role='EvmRole-approver'):
    return ac.Group(description='grp' + random.generate_random_string(),
                    role=role)


def new_role():
    return ac.Role(name='rol' + random.generate_random_string(),
                   vm_restriction='None')


# User test cases
def test_user_crud():
    user = new_user()
    user.create()
    with update(user):
        user.name = user.name + "edited"
    copied_user = user.copy()
    copied_user.delete()
    user.delete()


# @pytest.mark.bugzilla(1035399) # work around instead of skip
def test_user_login():
    user = new_user()
    user.create()
    try:
        login.login(user.credential.principal, user.credential.secret)
    finally:
        login.login_admin()


def test_user_duplicate_name():
    nu = new_user()
    nu.create()
    with error.expected("Userid has already been taken"):
        nu.create()

group_user = ac.Group("EvmGroup-user")


def test_username_required_error_validation():
    user = ac.User(
        name=None,
        credential=new_credential(),
        email='xyz@redhat.com',
        group=group_user)
    with error.expected("Name can't be blank"):
        user.create()


def test_userid_required_error_validation():
    user = ac.User(
        name='user' + random.generate_random_string(),
        credential=Credential(principal=None, secret='redhat'),
        email='xyz@redhat.com',
        group=group_user)
    with error.expected("Userid can't be blank"):
        user.create()


def test_user_password_required_error_validation():
    user = ac.User(
        name='user' + random.generate_random_string(),
        credential=Credential(principal='uid' + random.generate_random_string(), secret=None),
        email='xyz@redhat.com',
        group=group_user)
    with error.expected("Password_digest can't be blank"):
        user.create()


def test_user_group_error_validation():
    user = ac.User(
        name='user' + random.generate_random_string(),
        credential=new_credential(),
        email='xyz@redhat.com',
        group=None)
    with error.expected("A User must be assigned to a Group"):
        user.create()


def test_user_email_error_validation():
    user = ac.User(
        name='user' + random.generate_random_string(),
        credential=new_credential(),
        email='xyzdhat.com',
        group=group_user)
    with error.expected("Email must be a valid email address"):
        user.create()


# Group test cases
def test_group_crud():
    group = new_group()
    group.create()
    with update(group):
        group.description = group.description + "edited"
    group.delete()


# Role test cases
def test_role_crud():
    role = new_role()
    role.create()
    with update(role):
        role.name = role.name + "edited"
    role.delete()


def test_assign_user_to_new_group():
    role = new_role()  # call function to get role
    role.create()
    group = new_group(role=role.name)
    group.create()
    user = new_user(group=group)
    user.create()


def _test_cloud_provider_crud():
    print "entering _test_cloud_provider_crud"
    provider_utils.clear_cloud_providers()    # Start from baseline
    # Due to a bug in refreshing openstack providers, they are filtered out of the list of providers
    provider_list = [p for p in provider_utils.list_cloud_providers() if not p.startswith('rhos')]
    print provider_list
    random_provider = random.pick(provider_list, 1)[0]
    print "cloud: random_provider: " + random_provider
    provider_instance = provider_utils.setup_provider(random_provider, validate=False)
    print "cloud provider setup"
    provider_instance.update({'name': random_provider + '-edited'})
    print "Provider_instance.name: " + provider_instance.name
    print "cloud provider edited"
    provider_instance.delete(False)
    print "cloud provider deleted. Waiting for it to show up in CFME"
    provider_utils.wait_for_provider_delete(provider_instance)
    print "leaving _test_cloud_provider_crud"


def _test_infra_provider_crud():
    print "entering _test_infra_provider_crud"
    provider_utils.clear_infra_providers()    # Start from baseline
    print provider_utils.list_infra_providers()
    random_provider = random.pick(provider_utils.list_infra_providers(), 1)[0]
    print "infra: random_provider: " + random_provider
    provider_instance = provider_utils.setup_provider(random_provider, validate=False)
    print "infra provider setup"
    provider_instance.update({'name': random_provider + '-edited'})
    provider_instance.delete(False)
    print "Infra provider deleted. Waiting for it to show up in CFME"
    provider_utils.wait_for_provider_delete(provider_instance)
    print "leaving _test_infra_provider_crud"


def _mk_role(name=None, vm_restriction=None, product_features=None):
    '''Create a thunk that returns a Role object to be used for perm
       testing.  name=None will generate a random name

    '''
    name = name or random.generate_random_string()
    return lambda: ac.Role(name=name,
                           vm_restriction=vm_restriction,
                           product_features=product_features)


def _go_to(dest):
    '''Create a thunk that navigates to the given destination'''
    return lambda: nav.go_to(dest)


def _test_show_vms():
    """Check that no VMs exists under user"""
    user_vm_list = vms.get_all_vms()
    login.logout()
    login.login_admin()
    assert vms.get_all_vms() == user_vm_list


cat_name = version.pick({version.LOWEST: "Settings & Operations",
                         "5.3": "Configure"})


NAV_TESTS = {

    'my services': _go_to('my_services'),
    'chargeback': _go_to('chargeback'),
    'clouds providers': _go_to('clouds_providers'),
    'infrastructure providers': _go_to('infrastructure_providers'),
    'control explorer': _go_to('control_explorer'),
    'automate explorer': _go_to('automate_explorer'),
    'dashboard': _go_to('dashboard'),
    'virutal machines': _go_to('infrastructure_virtual_machines'),
    'configuration': _go_to('configuration'),
    'automate customization':_go_to('automate_customization'),
    'my settings': _go_to('my_settings'),
    'add provider': _go_to('infrastructure_provider_new'),
    'list vms': _test_show_vms

}


@pytest.mark.parametrize(
    'role,allowed_actions,disallowed_actions',
    [[_mk_role(product_features=[[['Everything'], False],  # minimal permission
                                 [[cat_name, 'Tasks'], True]]),
      {'tasks': lambda: sel.click(tasks.buttons.default)}, NAV_TESTS],  # can only access one thing
     [_mk_role(product_features=[[['Everything'], True]]), NAV_TESTS, {}]])  # full permissions
# @pytest.mark.bugzilla(1035399) # work around instead of skip
def test_permissions(role, allowed_actions, disallowed_actions):
    # create a user and role
    role = role()  # call function to get role
    role.create()
    group = new_group(role=role.name)
    group.create()
    user = new_user(group=group)
    user.create()
    fails = {}
    try:
        login.login(user.credential.principal, user.credential.secret)
        for name, action_thunk in allowed_actions.items():
            try:
                action_thunk()
            except Exception as e:
                raise e
                fails[name] = e
        for name, action_thunk in disallowed_actions.items():
            try:
                with error.expected(Exception):
                    print str(name) + ", " + str(action_thunk)
                    action_thunk()
            except error.UnexpectedSuccessException as e:
                raise e
                fails[name] = e
        if fails:
            raise Exception(fails)
    finally:
        login.login_admin()


def single_task_permission_test(product_features, actions):
    '''Tests that action succeeds when product_features are enabled, and
       fail when everything but product_features are enabled'''
    test_permissions(_mk_role(name=random.generate_random_string(),
                              product_features=[(['Everything'], False)] +
                              [(f, True) for f in product_features]),
                     actions,
                     {})
    test_permissions(_mk_role(name=random.generate_random_string(),
                              product_features=[(['Everything'], True)] +
                              [(f, False) for f in product_features]),
                     {},
                     actions)


def test_permissions_role_crud():
    single_task_permission_test([[cat_name, 'Configuration'],
                                 ['Services', 'Catalogs Explorer']],
                                {'Role CRUD': test_role_crud})


def test_permissions_cloud_provider_crud():
    single_task_permission_test([['Clouds', 'Cloud Providers', 'Modify'],
                                 ['Clouds', 'Cloud Providers', 'View'],
                                 ['Clouds', 'Cloud Providers','Operate', 'Refresh']],
                                {'Add cloud provider': _test_cloud_provider_crud})


def test_permissions_infra_provider_crud():
    single_task_permission_test([['Infrastructure', 'Infrastructure Providers', 'Modify'],
                                ['Infrastructure', 'Infrastructure Providers', 'View'],
                                ['Infrastructure', 'Infrastructure Providers',
                                    'Operate', 'Refresh']],
                                {'Add infrastructure provider': _test_infra_provider_crud})

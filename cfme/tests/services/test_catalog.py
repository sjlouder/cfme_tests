from cfme.services.catalogs.catalog import Catalog
import pytest
import utils.randomness as rand
from utils.update import update
import utils.error as error


pytestmark = [pytest.mark.usefixtures("logged_in")]


def test_catalog_crud():
    cat = Catalog(name=rand.generate_random_string(),
                  description="my catalog")
    cat.create()
    with update(cat):
        cat.description = "my edited description"
    cat.delete()


def test_catalog_duplicate_name():
    cat = Catalog(name=rand.generate_random_string(),
                  description="my catalog")
    cat.create()
    with error.expected("Name has already been taken"):
        cat.create()
    cat.delete()

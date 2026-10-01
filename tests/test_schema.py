import pytest
from pydantic import ValidationError

from ritualgraph.schema import Taxonomy


def test_ciap_does_not_accept_fidelity_as_fake_standard_dimension():
    with pytest.raises(ValidationError):
        Taxonomy(stride=["T"], ciap=["Fidelity"], nist_aml=["other"])

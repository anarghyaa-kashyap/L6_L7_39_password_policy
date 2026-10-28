import pytest
from password_policy import check_password, strength, suggest_fix


def test_valid_password_has_no_issues():
    assert check_password("Abcdef1!") == []


def test_valid_password_is_good():
    assert strength("Abcdef1!") == "good"


def test_too_short_password():
    assert check_password("Ab1!") == ["too short"]


def test_too_long_password():
    pw = "a" * 65
    assert check_password(pw) == ["too long", "no uppercase", "no digit", "no special"]


def test_common_password_and_no_lowercase():
    assert check_password("PASSWORD") == ["common", "no lowercase", "no digit", "no special"]


def test_strong_password():
    assert strength("Abcdefghijk1!@") == "strong"


def test_weak_password():
    assert strength("Abcdefgh1") == "weak"


def test_very_weak_password():
    assert strength("abc") == "very weak"


def test_suggest_fix_none_needed():
    assert suggest_fix([]) == "none needed"


def test_suggest_fix_too_short():
    assert suggest_fix(["too short"]) == "add more characters"


def test_suggest_fix_common():
    assert suggest_fix(["common"]) == "avoid common passwords"


def test_suggest_fix_missing_class():
    assert suggest_fix(["no digit"]) == "add digit"


def test_suggest_fix_too_long():
    assert suggest_fix(["too long"]) == "shorten it"

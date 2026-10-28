import pytest
from password_policy import COMMON, check_password, strength, suggest_fix


def test_valid_password_has_no_issues():
    assert check_password("Abcdef1!") == []


def test_valid_password_is_good():
    assert strength("Abcdef1!") == "good"


def test_length_seven_is_too_short():
    assert "too short" in check_password("Abcde1!")


def test_length_eight_is_not_too_short():
    assert "too short" not in check_password("Abcdef1!")


def test_length_sixty_four_is_not_too_long():
    pw = "Aa1!" * 16
    assert len(pw) == 64
    assert check_password(pw) == []


def test_length_sixty_five_is_too_long():
    pw = "Aa1!" * 16 + "a"
    assert len(pw) == 65
    assert check_password(pw) == ["too long"]


def test_short_password_never_reports_too_long():
    issues = check_password("Ab1!")
    assert "too short" in issues
    assert "too long" not in issues


def test_empty_password_skips_character_loop():
    assert check_password("") == ["too short", "no uppercase", "no lowercase", "no digit", "no special"]


@pytest.mark.parametrize("pw", sorted(COMMON))
def test_every_common_password_is_flagged(pw):
    assert "common" in check_password(pw)


def test_common_check_is_case_insensitive():
    assert "common" in check_password("PassWord")


def test_uncommon_password_not_flagged():
    assert "common" not in check_password("Abcdef1!")


def test_no_uppercase_branch():
    assert check_password("abcdef1!") == ["no uppercase"]


def test_no_lowercase_branch():
    assert check_password("ABCDEF1!") == ["no lowercase"]


def test_no_digit_branch():
    assert check_password("Abcdefg!") == ["no digit"]


def test_no_special_branch():
    assert check_password("Abcdefg1") == ["no special"]


def test_space_counts_as_special():
    assert check_password("Abc def1") == []


def test_issue_order_is_preserved():
    assert check_password("abc") == ["too short", "no uppercase", "no digit", "no special"]


def test_strength_strong_at_fourteen_chars():
    pw = "Abcdefghijk1!@"
    assert len(pw) == 14
    assert strength(pw) == "strong"


def test_strength_good_at_thirteen_chars():
    pw = "Abcdefghij1!@"
    assert len(pw) == 13
    assert strength(pw) == "good"


def test_strength_weak_with_one_issue():
    assert strength("Abcdefgh1") == "weak"


def test_strength_weak_with_exactly_two_issues():
    assert len(check_password("abcdefgh1")) == 2
    assert strength("abcdefgh1") == "weak"


def test_strength_very_weak_with_three_issues():
    assert len(check_password("abcdefgh")) == 3
    assert strength("abcdefgh") == "very weak"


def test_strength_very_weak_for_empty():
    assert strength("") == "very weak"


def test_suggest_fix_none_needed():
    assert suggest_fix([]) == "none needed"


def test_suggest_fix_too_short():
    assert suggest_fix(["too short", "no digit"]) == "add more characters"


def test_suggest_fix_common():
    assert suggest_fix(["common", "no digit"]) == "avoid common passwords"


@pytest.mark.parametrize(
    "issue, expected",
    [
        ("no uppercase", "add uppercase"),
        ("no lowercase", "add lowercase"),
        ("no digit", "add digit"),
        ("no special", "add special"),
    ],
)
def test_suggest_fix_missing_class(issue, expected):
    assert suggest_fix([issue]) == expected


def test_suggest_fix_too_long():
    assert suggest_fix(["too long", "no digit"]) == "shorten it"


def test_suggest_fix_uses_only_first_issue():
    assert suggest_fix(["no digit", "too short"]) == "add digit"


def test_end_to_end_fix_for_real_password():
    assert suggest_fix(check_password("password")) == "avoid common passwords"

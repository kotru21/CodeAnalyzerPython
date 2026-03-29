from eval.dataset_github import (
    github_blob_to_raw_url,
    parse_csv_int,
    parse_github_blob_url,
)


def test_parse_blob_url_typical() -> None:
    u = "https://github.com/angular/angular.js/blob/f6aa1c55616b34215f562e0445e436210860ef04/src/ng/compile.js"
    assert parse_github_blob_url(u) == (
        "angular",
        "angular.js",
        "f6aa1c55616b34215f562e0445e436210860ef04",
        "src/ng/compile.js",
    )


def test_raw_url() -> None:
    blob = "https://github.com/angular/angular.js/blob/abc123/src/ng/compile.js"
    assert github_blob_to_raw_url(blob) == (
        "https://raw.githubusercontent.com/angular/angular.js/abc123/src/ng/compile.js"
    )


def test_parse_csv_int_plain() -> None:
    assert parse_csv_int("942") == 942


def test_parse_csv_int_european_thousands() -> None:
    assert parse_csv_int("1.200") == 1200

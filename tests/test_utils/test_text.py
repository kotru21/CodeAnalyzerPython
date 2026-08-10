import hashlib

from analyzer.utils.hash import md5_fingerprint, sha256_digest
from analyzer.utils.text import encode_utf8_safe, sanitize_lone_surrogates


class TestSanitizeLoneSurrogates:
    def test_lone_high_surrogate_replaced(self) -> None:
        assert sanitize_lone_surrogates("const s = '\ud800';") == "const s = '\ufffd';"

    def test_lone_low_surrogate_replaced(self) -> None:
        assert sanitize_lone_surrogates("a\udfff") == "a\ufffd"

    def test_valid_surrogate_pair_emoji_preserved(self) -> None:
        text = "emoji \U0001f600 ok"
        assert sanitize_lone_surrogates(text) == text

    def test_bom_preserved(self) -> None:
        text = "\ufeffconst x = 1;"
        assert sanitize_lone_surrogates(text) == text

    def test_non_ascii_preserved(self) -> None:
        text = "const s = 'пароль — ünïcodé';"
        assert sanitize_lone_surrogates(text) == text

    def test_plain_ascii_unchanged(self) -> None:
        text = "const x = 1 + 2;"
        assert sanitize_lone_surrogates(text) == text

    def test_surrogate_pair_after_lone_high_combined(self) -> None:
        assert sanitize_lone_surrogates("\ud800\ud800\udc00") == "\ufffd\U00010000"


class TestEncodeUtf8Safe:
    def test_lone_surrogate_does_not_raise(self) -> None:
        data = encode_utf8_safe("const s = '\ud800';")
        assert data == "const s = '\ufffd';".encode("utf-8")

    def test_matches_strict_encode_for_clean_text(self) -> None:
        text = "emoji \U0001f600 and ünïcodé"
        assert encode_utf8_safe(text) == text.encode("utf-8")

    def test_explicit_surrogate_pair_encodes_as_scalar(self) -> None:
        pair = chr(0xD83D) + chr(0xDE00)
        assert encode_utf8_safe(pair) == "\U0001f600".encode("utf-8")


class TestHashHelpersWithSurrogates:
    def test_sha256_digest_tolerates_lone_surrogate(self) -> None:
        expected = hashlib.sha256(encode_utf8_safe("x\ud800")).hexdigest()
        assert sha256_digest("x\ud800") == expected

    def test_md5_fingerprint_tolerates_lone_surrogate(self) -> None:
        expected = hashlib.md5(encode_utf8_safe("a:\ufffd")).hexdigest()
        assert md5_fingerprint("a", "\ud800") == expected

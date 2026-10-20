"""Key handling: the one place that turns a user's string into bytes."""

from __future__ import annotations

import pytest

from wacrypt.core import keys as keysmod

GOOD = bytes(range(32)).hex()


class TestParseHexKey:
    @pytest.mark.parametrize(
        "given",
        [GOOD, GOOD.upper(), f"  {GOOD}\n", f'"{GOOD}"', f"0x{GOOD}", GOOD[:32] + " " + GOOD[32:]],
    )
    def test_accepts_the_shapes_users_paste(self, given):
        assert keysmod.parse_hex_key(given) == bytes(range(32))

    @pytest.mark.parametrize(
        "given", ["", "short", GOOD + "0", GOOD[:-1], "z" * 64, "not a key", GOOD + "00"]
    )
    def test_rejects_everything_else(self, given):
        with pytest.raises(keysmod.KeyError_):
            keysmod.parse_hex_key(given)


class TestKeyFile:
    def test_a_hex_text_file(self, tmp_path):
        path = tmp_path / "key.txt"
        path.write_text(GOOD + "\n")
        assert keysmod.load_key_file(path) == bytes(range(32))

    def test_raw_bytes(self, tmp_path):
        path = tmp_path / "key.key"
        path.write_bytes(bytes(range(32)))
        assert keysmod.load_key_file(path) == bytes(range(32))

    def test_a_crypt14_serialised_array(self, tmp_path):
        path = tmp_path / "crypt14.key"
        path.write_bytes(b"\xac\xed\x00\x05\x75\x72\x00\x02[" + b"x" * 20
                         + b"\x74\x00\x20" + bytes(range(32)) + b"rest")
        assert keysmod.load_key_file(path) == bytes(range(32))

    def test_missing_file_is_named(self, tmp_path):
        with pytest.raises(keysmod.KeyError_, match="not found"):
            keysmod.load_key_file(tmp_path / "nope")


class TestKeychain:
    def test_round_trip(self):
        key = bytes(range(32))
        assert keysmod.vault_set(key) is True
        assert keysmod.vault_get() == key

    def test_status_is_redacted(self):
        keysmod.vault_set(bytes(range(32)))
        status = keysmod.vault_status()
        assert status.startswith(GOOD[:6])
        assert GOOD not in status

    def test_forget(self):
        keysmod.vault_set(bytes(range(32)))
        assert keysmod.vault_delete() is True
        assert keysmod.vault_get() is None

    def test_garbage_in_the_keychain_is_ignored(self):
        import keyring

        keyring.set_password(keysmod.SERVICE, keysmod.ACCOUNT, "not a key")
        assert keysmod.vault_get() is None


class TestResolve:
    def test_a_literal_key_wins_over_the_keychain(self):
        keysmod.vault_set(b"\xff" * 32)
        assert keysmod.resolve_key(GOOD) == bytes(range(32))

    def test_a_file_is_accepted(self, tmp_path):
        path = tmp_path / "k.txt"
        path.write_text(GOOD)
        assert keysmod.resolve_key(str(path)) == bytes(range(32))

    def test_the_keychain_is_used_when_nothing_is_given(self):
        keysmod.vault_set(bytes(range(32)))
        assert keysmod.resolve_key() == bytes(range(32))

    def test_nothing_available_is_reported(self):
        with pytest.raises(keysmod.KeyError_, match="no key"):
            keysmod.resolve_key(allow_prompt=False, use_vault=False)

    def test_a_nonsense_value_is_explained(self):
        with pytest.raises(keysmod.KeyError_):
            keysmod.resolve_key("neither a key nor a file", use_vault=False,
                                allow_prompt=False)

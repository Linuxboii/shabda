import unittest

from shabda.identify import identify


def names(hash_str):
    return [c.name for c in identify(hash_str)]


class TestIdentify(unittest.TestCase):
    def test_md5_length(self):
        top = identify("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual(top[0].name, "MD5")
        self.assertEqual(top[0].hashcat, "0")
        self.assertIn("NTLM", names("5f4dcc3b5aa765d61d8327deb882cf99"))

    def test_sha1(self):
        top = identify("a" * 40)
        self.assertEqual(top[0].name, "SHA1")

    def test_sha256(self):
        top = identify("a" * 64)
        self.assertEqual(top[0].name, "SHA-256")

    def test_sha512(self):
        top = identify("a" * 128)
        self.assertEqual(top[0].name, "SHA-512")

    def test_bcrypt_prefix(self):
        h = "$2b$12$" + "." * 53
        top = identify(h)
        self.assertEqual(top[0].name, "bcrypt")
        self.assertEqual(top[0].hashcat, "3200")

    def test_sha512crypt_prefix(self):
        top = identify("$6$salt$" + "a" * 86)
        self.assertTrue(top[0].name.startswith("sha512crypt"))

    def test_argon2id(self):
        top = identify("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaA")
        self.assertEqual(top[0].name, "Argon2id")

    def test_mysql41(self):
        top = identify("*" + "A" * 40)
        self.assertTrue(top[0].name.startswith("MySQL4.1+"))

    def test_crc32(self):
        self.assertIn("CRC32", names("1234abcd"))

    def test_phpass(self):
        top = identify("$P$" + "B" * 31)
        self.assertTrue(top[0].name.startswith("phpass"))

    def test_empty_and_unknown(self):
        self.assertEqual(identify(""), [])
        self.assertEqual(identify("   "), [])
        self.assertEqual(identify("xyz!!!not a hash"), [])

    def test_confidence_sorted(self):
        cands = identify("a" * 32)
        order = {"high": 0, "medium": 1, "low": 2}
        vals = [order[c.confidence] for c in cands]
        self.assertEqual(vals, sorted(vals))


if __name__ == "__main__":
    unittest.main()

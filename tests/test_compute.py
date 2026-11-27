import unittest

from verbum_shabda.compute import compute
from verbum_shabda.md4 import md4


class TestCompute(unittest.TestCase):
    def test_md5(self):
        self.assertEqual(
            compute("md5", b"password"), "5f4dcc3b5aa765d61d8327deb882cf99"
        )

    def test_sha1(self):
        self.assertEqual(
            compute("sha1", b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d"
        )

    def test_sha256(self):
        self.assertEqual(
            compute("sha256", b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_md4_rfc1320_vectors(self):
        self.assertEqual(md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(md4(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")
        self.assertEqual(
            md4(b"message digest").hex(), "d9130a8164549fe818874806e1c7014b"
        )

    def test_ntlm(self):
        # NTLM("password") is a well-known value.
        self.assertEqual(
            compute("ntlm", b"password"), "8846f7eaee8fb117ad06bdd830b7586c"
        )

    def test_unknown_algo(self):
        with self.assertRaises(ValueError):
            compute("nope", b"x")


if __name__ == "__main__":
    unittest.main()


import pytest
import logging
import gpgmime

# These are pytest fixtures; while we don't use them explicitly in the module
# below, they're used implicitly due to the parameter names of the tests. This
# may throw off some static analysis tools (e.g. python-mode throws an error
# about an unused import).
from testing.utils import msg, gpg

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestSignAndEncrypt:
    """Each of these tests verifies a few things:

    1. The operation in question doesn't blow up.
    2. The operation doesn't modify the original message.
    3. The result is consistent with is_signed and is_encrypted.
    """

    def test_sign_encrypt_onestep(self, gpg, msg):
        msg_text = msg.as_string()
        ret = gpg.sign_and_encrypt_email(msg,
                                         '4EF877BDEEE0DDA6C9C3F9F51B83C7515522668B',
                                         default_key='E5697DAF0A970F4E6BC61F03554B93BB1BF2F918',
                                         passphrase='secret')

        assert gpgmime.is_encrypted(ret)
        assert not gpgmime.is_signed(ret)  # Per is_signed's docstring, there
                                           # is no way to tell if the message
                                           # is also encrypted.
        assert msg.as_string() == msg_text
        logger.debug("one-step output: %r", ret.as_string())

    def test_sign_then_encrypt(self, gpg, msg):
        msg_text = msg.as_string()

        signed = gpg.sign_email(msg,
                                default_key='E5697DAF0A970F4E6BC61F03554B93BB1BF2F918',
                                passphrase='secret')
        assert gpgmime.is_signed(signed)

        assert msg.as_string() == msg_text
        signed_text = signed.as_string()

        encrypted = gpg.encrypt_email(signed, '4EF877BDEEE0DDA6C9C3F9F51B83C7515522668B')
        assert gpgmime.is_encrypted(encrypted)
        assert not gpgmime.is_signed(encrypted)

        assert signed.as_string() == signed_text

        logger.debug("two-step output: %r", encrypted.as_string())


def test_encrypt_decrypt(gpg, msg):
    orig_body = msg.get_payload()

    msg = gpg.encrypt_email(msg, '4EF877BDEEE0DDA6C9C3F9F51B83C7515522668B')
    assert gpgmime.is_encrypted(msg)

    msg, decrypted = gpg.decrypt_email(msg)
    assert decrypted

    # We really ought to check as much of the headers as we can, but it's a bit
    # tricky to make sure they're textually *identical*. Let's at least check
    # that the body comes out right:
    assert msg.get_payload() == orig_body


@pytest.mark.xfail()
def test_sign_verify(gpg, msg):
    ret = gpg.sign_email(msg, default_key='E5697DAF0A970F4E6BC61F03554B93BB1BF2F918', passphrase='secret')
    assert gpgmime.is_signed(ret)
    verified = gpg.verify_email(ret)
    assert verified

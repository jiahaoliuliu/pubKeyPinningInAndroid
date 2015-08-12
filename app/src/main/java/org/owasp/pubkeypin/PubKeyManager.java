package org.owasp.pubkeypin;

import android.util.Log;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

// Many thanks to Nikolay Elenkov for feedback.
// Shamelessly based upon Moxie's example code (AOSP/Google did not offer code)
// http://www.thoughtcrime.org/blog/authenticity-is-broken-in-ssl-but-your-app-ha/
public final class PubKeyManager implements X509TrustManager {

    private static final String TAG = "PubKeyManager";

	// DER encoded public key
    // The original public key
//	private static String PUB_KEY =
//			"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7O3HQWLnTzCCj/qwoI4v" +
//			"j/T9237we74rwcJW2w4SuzIKVlAn5yhaJcaeQpdpmHwmQt3aU8G1ba7n3xl7hdeP" +
//			"kh+aEkYM3iVOhJZdkCKjzw2x7lUSQInZksgns8R4iGklJPInX6fmBjErt1YrjI8B" +
//			"5Hqz3koibkqIZgVuZ1QfJogbmsrT64imgiDdeG3XDcOY4yDzS734bNqRUNYha3aD" +
//			"nwvxrubyMhfWtBl2y6nXKDbeMKJ9NWu723V7L+BGFeEvYMPq8ieRVJ7ycavKeSXE" +
//			"oi9GvgzCjuy2GBJOXs41O5f07VnqGxci6uqyblEgr0SoNETYFnJsSVkryyTPtO7l" +
//			"h5jdFg4QmHBUEfzfcWQMkxj4LbDvRHMn5UIrofkA7g+97Wf/IQnZzhlZh+DgIb3j" +
//			"jXD50GqJsd7cd0ojJZuzGf6BLSZ8g2KZOJ3KtB1u/nZ4HVQUdP6ZNop3mEx7Miar" +
//			"7wSDjRzGg4ayfxHa8pOtE6o8pe0d7lVu3XTHC9kL5qZ3Xqld6Sx9tJ2ZQ2oDjTPl" +
//			"PIhYGMLdeEhXmYUrhnDChpOJrWvsb/eh4M38sWUccBQTl9sBvWRkrbSCazlxZA+Y" +
//			"5KOPEJ3NIR8GjKFNwbd8Bk9Yk3LnbocSp3E82BVD1gi4zRd9MtBhClGc//xi8S5W" +
//			"rFho8l+sZ+dCq/iuVYLTkGUCAwEAAQ==";

    private static String PUB_KEY =
            "30820222300d06092a864886f70d01010105000382020f003082020a028202010" +
            "0ecedc74162e74f30828ffab0a08e2f8ff4fddb7ef07bbe2bc1c256db0e12bb32" +
            "0a565027e7285a25c69e429769987c2642ddda53c1b56daee7df197b85d78f921" +
            "f9a12460cde254e84965d9022a3cf0db1ee55124089d992c827b3c47888692524" +
            "f2275fa7e606312bb7562b8c8f01e47ab3de4a226e4a8866056e67541f26881b9" +
            "acad3eb88a68220dd786dd70dc398e320f34bbdf86cda9150d6216b76839f0bf1" +
            "aee6f23217d6b41976cba9d72836de30a27d356bbbdb757b2fe04615e12f60c3e" +
            "af22791549ef271abca7925c4a22f46be0cc28eecb618124e5ece353b97f4ed59" +
            "ea1b1722eaeab26e5120af44a83444d816726c49592bcb24cfb4eee58798dd160" +
            "e1098705411fcdf71640c9318f82db0ef447327e5422ba1f900ee0fbded67ff21" +
            "09d9ce195987e0e021bde38d70f9d06a89b1dedc774a23259bb319fe812d267c8" +
            "36299389dcab41d6efe76781d541474fe99368a77984c7b3226abef04838d1cc6" +
            "8386b27f11daf293ad13aa3ca5ed1dee556edd74c70bd90be6a6775ea95de92c7" +
            "db49d99436a038d33e53c885818c2dd78485799852b8670c2869389ad6bec6ff7" +
            "a1e0cdfcb1651c70141397db01bd6464adb4826b3971640f98e4a38f109dcd211" +
            "f068ca14dc1b77c064f589372e76e8712a7713cd81543d608b8cd177d32d0610a" +
            "519cfffc62f12e56ac5868f25fac67e742abf8ae5582d390650203010001";

	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {

		assert (chain != null);
		if (chain == null) {
			throw new IllegalArgumentException(
					"checkServerTrusted: X509Certificate array is null");
		}

		assert (chain.length > 0);
		if (!(chain.length > 0)) {
			throw new IllegalArgumentException(
					"checkServerTrusted: X509Certificate is empty");
		}

		assert (null != authType && authType.equalsIgnoreCase("ECDHE_RSA"));
		if (!(null != authType && authType.equalsIgnoreCase("ECDHE_RSA"))) {
			throw new CertificateException(
					"checkServerTrusted: AuthType is not ECDHE_RSA");
		}

		// Perform customary SSL/TLS checks
		TrustManagerFactory tmf;
		try {
			tmf = TrustManagerFactory.getInstance("X509");
			tmf.init((KeyStore) null);

			for (TrustManager trustManager : tmf.getTrustManagers()) {
				((X509TrustManager) trustManager).checkServerTrusted(
						chain, authType);
			}

		} catch (Exception e) {
			throw new CertificateException(e);
		}

		// Hack ahead: BigInteger and toString(). We know a DER encoded Public
		// Key starts with 0x30 (ASN.1 SEQUENCE and CONSTRUCTED), so there is
		// no leading 0x00 to drop.
		RSAPublicKey pubkey = (RSAPublicKey) chain[0].getPublicKey();
        Log.v(TAG, "The pub key obtained is " + pubkey.toString());

		String encoded = new BigInteger(1 /* positive */, pubkey.getEncoded())
				.toString(16);

		// Pin it!
		final boolean expected = PUB_KEY.equalsIgnoreCase(encoded);
        Log.v(TAG, "got encoded key as " + encoded);

		assert(expected);
		if (!expected) {
			throw new CertificateException(
					"checkServerTrusted: Expected public key: " + PUB_KEY
							+ ", got public key:" + encoded);
		}
	}

	public void checkClientTrusted(X509Certificate[] xcs, String string) {
		// throw new
		// UnsupportedOperationException("checkClientTrusted: Not supported yet.");
	}

	public X509Certificate[] getAcceptedIssuers() {
		// throw new
		// UnsupportedOperationException("getAcceptedIssuers: Not supported yet.");
		return null;
	}
}

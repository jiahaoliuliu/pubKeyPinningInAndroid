package org.owasp.pubkeypin;

import android.util.Base64;
import android.util.Log;

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
// Fixed the problem with encoding by using solution in StackOverFlow:
// http://stackoverflow.com/questions/28667575/pinning-public-key-in-my-app
public final class PubKeyManager implements X509TrustManager {

    private static final String TAG = "PubKeyManager";

    // DER encoded public key
    private static String PUB_KEY =
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7O3HQWLnTzCCj/qwoI4v" +
            "j/T9237we74rwcJW2w4SuzIKVlAn5yhaJcaeQpdpmHwmQt3aU8G1ba7n3xl7hdeP" +
            "kh+aEkYM3iVOhJZdkCKjzw2x7lUSQInZksgns8R4iGklJPInX6fmBjErt1YrjI8B" +
            "5Hqz3koibkqIZgVuZ1QfJogbmsrT64imgiDdeG3XDcOY4yDzS734bNqRUNYha3aD" +
            "nwvxrubyMhfWtBl2y6nXKDbeMKJ9NWu723V7L+BGFeEvYMPq8ieRVJ7ycavKeSXE" +
            "oi9GvgzCjuy2GBJOXs41O5f07VnqGxci6uqyblEgr0SoNETYFnJsSVkryyTPtO7l" +
            "h5jdFg4QmHBUEfzfcWQMkxj4LbDvRHMn5UIrofkA7g+97Wf/IQnZzhlZh+DgIb3j" +
            "jXD50GqJsd7cd0ojJZuzGf6BLSZ8g2KZOJ3KtB1u/nZ4HVQUdP6ZNop3mEx7Miar" +
            "7wSDjRzGg4ayfxHa8pOtE6o8pe0d7lVu3XTHC9kL5qZ3Xqld6Sx9tJ2ZQ2oDjTPl" +
            "PIhYGMLdeEhXmYUrhnDChpOJrWvsb/eh4M38sWUccBQTl9sBvWRkrbSCazlxZA+Y" +
            "5KOPEJ3NIR8GjKFNwbd8Bk9Yk3LnbocSp3E82BVD1gi4zRd9MtBhClGc//xi8S5W" +
            "rFho8l+sZ+dCq/iuVYLTkGUCAwEAAQ==";

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

        RSAPublicKey pubkey = (RSAPublicKey) chain[0].getPublicKey();

        // Solution found in
        // http://stackoverflow.com/questions/28667575/pinning-public-key-in-my-app
        String base64Encoded = Base64.encodeToString(pubkey.getEncoded(), Base64.DEFAULT)
                .replace("\n", "");

        // Pin it!
        final boolean expected = PUB_KEY.equalsIgnoreCase(base64Encoded);
        Log.v(TAG, "got encoded key as " + base64Encoded);

        assert(expected);
        if (!expected) {
            throw new CertificateException(
                    "checkServerTrusted: Expected public key: " + PUB_KEY
                            + ", got public key:" + base64Encoded);
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

package org.apache.commons.httpclient.protocol;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.Principal;
import java.security.cert.X509Certificate;

public class TestHostnameVerifier {

    @Test
    public void testExtractCN() {
        Assert.assertArrayEquals(new String[] {"blah"}, SSLProtocolSocketFactory.extractCNs("cn=blah, ou=blah, o=blah"));
        Assert.assertArrayEquals(new String[] {"blah", "yada", "booh"}, SSLProtocolSocketFactory.extractCNs("cn=blah, cn=yada, cn=booh"));
        Assert.assertArrayEquals(new String[] {"blah"}, SSLProtocolSocketFactory.extractCNs("cn=\"blah\", ou=blah, o=blah"));
        Assert.assertArrayEquals(new String[] {"blah  blah"}, SSLProtocolSocketFactory.extractCNs("cn=\"blah  blah\", ou=blah, o=blah"));
        Assert.assertArrayEquals(new String[] {"blah"}, SSLProtocolSocketFactory.extractCNs("cn=\"blah, blah\", ou=blah, o=blah"));
        Assert.assertArrayEquals(new String[] {"blah"}, SSLProtocolSocketFactory.extractCNs("cn=blah\\, blah, ou=blah, o=blah"));
        Assert.assertArrayEquals(new String[] {"blah"}, SSLProtocolSocketFactory.extractCNs("c = cn=uuh, cn=blah, ou=blah, o=blah"));
    }

    @Test
    public void testExtractCNInvalid1() {
        Assert.assertNull(SSLProtocolSocketFactory.extractCNs("blah,blah"));
    }

    @Test
    public void testExtractCNInvalid2() {
        Assert.assertNull(SSLProtocolSocketFactory.extractCNs("cn,o=blah"));
        Assert.assertNull(SSLProtocolSocketFactory.extractCNs("cn=   , ou=blah, o=blah"));
        Assert.assertNull(SSLProtocolSocketFactory.extractCNs("c = pampa ,  cn  =    blah    , ou = blah , o = blah"));
    }

    /**
     * https://github.com/apache/httpcomponents-client/commit/6e14fc146a66e0f3eb362f45f95d1a58ee18886a#diff-86f9553d730cd40ee3761aff31060220c2185ad6dc18e23caf753851d48f7074R351
     */
    @Test
    public void testGetCNs() {
        Principal principal = Mockito.mock(Principal.class);
        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Mockito.when(cert.getSubjectDN()).thenReturn(principal);
        Mockito.when(principal.toString()).thenReturn("bla,  bla, blah");
        Assert.assertArrayEquals(null, SSLProtocolSocketFactory.extractCNs(principal.toString()));
        Mockito.when(principal.toString()).thenReturn("Cn=,  Cn=  , CN, OU=CN=");
        Assert.assertArrayEquals(null, SSLProtocolSocketFactory.extractCNs(principal.toString()));
        Mockito.when(principal.toString()).thenReturn("  Cn=blah,  CN= blah , OU=CN=yada");
        Assert.assertArrayEquals(new String[] {"blah", " blah"}, SSLProtocolSocketFactory.extractCNs(principal.toString()));
    }
}

package org.xoolibeut.security.tls;


import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpsTrustManager implements X509TrustManager {
	private static TrustManager[] trustManagers;
	private static final X509Certificate[] _AcceptedIssuers = new X509Certificate[] {};
	private static final Logger LOGGER = LoggerFactory.getLogger(HttpsTrustManager.class);
	
	public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
			throws java.security.cert.CertificateException {

	}

	
	public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
			throws java.security.cert.CertificateException {

	}

	public boolean isClientTrusted(X509Certificate[] chain) {
		return true;
	}

	public boolean isServerTrusted(X509Certificate[] chain) {
		return true;
	}

	
	public X509Certificate[] getAcceptedIssuers() {
		return _AcceptedIssuers;
	}

	public static CustomSSLSocketFactory allowAllSSL(String protocole, String cipher) {
		HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {

		
			public boolean verify(String arg0, SSLSession arg1) {
				return true;
			}

		});

		SSLContext context = null;
		if (trustManagers == null) {
			trustManagers = new TrustManager[] { new HttpsTrustManager() };
		}

		try {
			context = SSLContext.getInstance("TLS");
			context.init(null, trustManagers, new SecureRandom());
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("allowAllSSL .",e.getMessage());
		} catch (KeyManagementException e) {
			LOGGER.error("allowAllSSL .",e.getMessage());
		} 

		// HttpsURLConnection.setDefaultSSLSocketFactory(context != null ?
		// context.getSocketFactory() : null);
		CustomSSLSocketFactory customSSLSocketFactory = new CustomSSLSocketFactory(context.getSocketFactory(),
				protocole, cipher);
		HttpsURLConnection.setDefaultSSLSocketFactory(customSSLSocketFactory);
		return customSSLSocketFactory;
	}

	public static CustomSSLSocketFactory allowAllSSL() {
		return allowAllSSL(null, null);
	}
}
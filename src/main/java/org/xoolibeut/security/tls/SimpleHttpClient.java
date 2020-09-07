package org.xoolibeut.security.tls;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleHttpClient {
	private static final Logger LOGGER = LoggerFactory.getLogger(SimpleHttpClient.class);

	public static void testSSL(String request) throws Exception {
		URL url = new URL(request);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		int responseCode = conn.getResponseCode();
		LOGGER.debug("response code " + responseCode);
		if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_BAD_REQUEST) { // success
			BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();

			LOGGER.debug(response.toString());
		}

	}

	public static void testSSL(String request, final Properties prop) throws Exception {
		URL url = new URL(request);
		HttpURLConnection conn;
		if (Boolean.valueOf(prop.getProperty("active.proxy"))) {
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(prop.getProperty("proxy.ip"),
					Integer.parseInt(prop.getProperty("proxy.port"))));
			Authenticator authenticator = new Authenticator() {
				public PasswordAuthentication getPasswordAuthentication() {
					return (new PasswordAuthentication(prop.getProperty("proxy.username"),
							prop.getProperty("proxy.password").toCharArray()));
				}
			};
			Authenticator.setDefault(authenticator);
			conn = (HttpURLConnection) url.openConnection(proxy);
		} else {
			conn = (HttpURLConnection) url.openConnection();
		}

		int responseCode = conn.getResponseCode();
		LOGGER.debug("response code " + responseCode);
		if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_BAD_REQUEST) { // success
			BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();
			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();
			LOGGER.debug(response.toString());
		}

	}
}

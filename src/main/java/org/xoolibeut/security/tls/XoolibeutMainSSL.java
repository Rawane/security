package org.xoolibeut.security.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.SSLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;

public class XoolibeutMainSSL {
	private static final Logger LOGGER = LoggerFactory.getLogger(XoolibeutMainSSL.class);

	public static void main(String[] args) {
		String urlTest = "https://google.fr";
		if (args.length > 0) {
			urlTest = args[0];
			if (!urlTest.contains("https://")) {
				urlTest = "https://" + urlTest;
			}
			urlTest = urlTest.replace("http://", "https://");
		}
		if (args.length > 1) {
			ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory
					.getLogger(Logger.ROOT_LOGGER_NAME);
			root.setLevel(Level.toLevel(args[1], Level.INFO));
		}
		LOGGER.info("Démarrage check tsl ........................................ " + urlTest);
		Map<String, Map<String, String>> mapProtocole = new HashMap<String, Map<String, String>>();
		Properties prop = readApplicationProperties();
		String[] protocols = null;
		String[] ciphers = null;
		Boolean useParmIn = Boolean.valueOf(prop.getProperty("use.protocoleandcipher"));
		if (useParmIn) {
			if (prop.getProperty("protocole.list") != null) {
				protocols = prop.getProperty("protocole.list").split(";");
			}
			if (prop.getProperty("cipher.list") != null) {
				ciphers = prop.getProperty("cipher.list").split(";");
			}
			if (protocols != null && ciphers != null) {
				for (int i = 0; i < protocols.length; i++) {
					LOGGER.debug("Protocol " + protocols[i]);
					Map<String, String> mapCipher = new HashMap<String, String>();
					try {
						for (int j = 0; j < ciphers.length; j++) {
							LOGGER.debug("Cipher " + ciphers[j] + " rang " + j);
							try {
								HttpsTrustManager.allowAllSSL(protocols[i].trim(), ciphers[j].trim());
								SimpleHttpClient.testSSL(urlTest, prop);
								mapCipher.put(ciphers[j], "yess");
								LOGGER.debug("cipher yess " + ciphers[j] + " rang " + j);
							} catch (Exception e) {
								e.printStackTrace();
								LOGGER.debug("Cipher not work " + ciphers[j] + " rang " + j);
								mapCipher.put(ciphers[j], "ko");
							}
							mapProtocole.put(protocols[i], mapCipher);
						}
					} catch (Exception e) {

						LOGGER.debug("Protocol or cipher not work " + protocols[i]);
					}
				}
			}

		} else {
			// initialisation
			CustomSSLSocketFactory customSSLSocketFactory = HttpsTrustManager.allowAllSSL();
			try {
				SimpleHttpClient.testSSL(urlTest, prop);
			} catch (Exception e) {
				e.printStackTrace();
				LOGGER.debug("problème initialisation ");
			}
			protocols = customSSLSocketFactory.getEnabledProtocols();
			try {
				SimpleHttpClient.testSSL(urlTest, prop);
			} catch (Exception e) {
				e.printStackTrace();
				LOGGER.debug("Recupération des protocols ");
			}
			for (int i = 0; i < protocols.length; i++) {
				LOGGER.debug("Protocol " + protocols[i]);
				Map<String, String> mapCipher = new HashMap<String, String>();
				try {
					customSSLSocketFactory = HttpsTrustManager.allowAllSSL(protocols[i], null);
					try {
						SimpleHttpClient.testSSL(urlTest, prop);
					} catch (Exception e) {
						LOGGER.error("Exception Message ", e.getMessage());
						if (e instanceof IllegalArgumentException) {
							LOGGER.error("IllegalArgumentException First Cipher in list not wok", e.getMessage());
						} else {
							if (e instanceof SSLException) {
								LOGGER.error(" SSLException First Cipher in list not wok", e.getMessage());
							}
						}

					}
					ciphers = customSSLSocketFactory.getEnableCiphers();
					for (int j = 0; i < ciphers.length; j++) {
						LOGGER.debug("Cipher " + ciphers[j] + " rang " + j);

						try {
							customSSLSocketFactory = HttpsTrustManager.allowAllSSL(protocols[i], ciphers[j]);
							SimpleHttpClient.testSSL(urlTest, prop);
							mapCipher.put(ciphers[j], "yess");
							LOGGER.debug("cipher yess " + ciphers[j] + " rang " + j);
						} catch (Exception e) {

							LOGGER.debug("Cipher not woork " + ciphers[j] + " rang " + j);
							mapCipher.put(ciphers[j], "ko");
						}
						mapProtocole.put(protocols[i], mapCipher);

					}
				} catch (Exception e) {
					LOGGER.error("Protocol not woork " + protocols[i], e.getMessage());
					LOGGER.debug("Protocol not woork " + protocols[i]);
				}
			}

		}
		LOGGER.info("Résumé scan ssl/tls ");
		Iterator<String> iteratorProtocol = mapProtocole.keySet().iterator();
		while (iteratorProtocol.hasNext()) {
			String key = iteratorProtocol.next();
			LOGGER.info("");
			LOGGER.info("Protocol " + key);
			Map<String, String> mapCipher = mapProtocole.get(key);
			Iterator<String> iteratorCipher = mapCipher.keySet().iterator();
			while (iteratorCipher.hasNext()) {
				String keyCipher = iteratorCipher.next();
				if ("yess".equals(mapCipher.get(keyCipher))) {
					LOGGER.info(keyCipher);
				}
			}
		}
		LOGGER.debug("---------------------------------------------------------------------");
		Iterator<String> iteratorProtocol2 = mapProtocole.keySet().iterator();
		while (iteratorProtocol2.hasNext()) {
			String key = iteratorProtocol2.next();
			LOGGER.debug("Protocol " + key);
			Map<String, String> mapCipher = mapProtocole.get(key);
			Iterator<String> iteratorCipher = mapCipher.keySet().iterator();
			while (iteratorCipher.hasNext()) {
				String keyCipher = iteratorCipher.next();
				LOGGER.debug(keyCipher + "  " + mapCipher.get(keyCipher));
			}
		}
		LOGGER.info("............... Fin check ssl");
	}

	private static Properties readApplicationProperties() {
		Properties prop = new Properties();
		InputStream is = null;
		is = XoolibeutMainSSL.class.getResourceAsStream("/application.properties");
		try {
			prop.load(is);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return prop;
	}
}

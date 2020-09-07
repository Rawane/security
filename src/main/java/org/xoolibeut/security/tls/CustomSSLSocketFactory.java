package org.xoolibeut.security.tls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomSSLSocketFactory extends SSLSocketFactory {
	SSLSocketFactory factory = null;
	private String tlsSelect;
	private String cipherSelect;
	private String[] enabledProtocols;
	private String[] enableCiphers;
	private static final Logger LOGGER =LoggerFactory.getLogger(CustomSSLSocketFactory.class);
	public CustomSSLSocketFactory(SSLSocketFactory factory) {
		this.factory = factory;
	}

	public CustomSSLSocketFactory(SSLSocketFactory factory, String protocole, String cipher) {
		this.factory = factory;
		this.tlsSelect = protocole;
		this.cipherSelect = cipher;
	}

	@Override
	public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
		LOGGER.debug("createSocket 3 ");
		Socket skt = factory.createSocket(s, host, port, autoClose);
		SSLSocket sslSocket = ((SSLSocket) skt);

		this.enabledProtocols = sslSocket.getEnabledProtocols();
		this.enableCiphers = sslSocket.getEnabledCipherSuites();
		if (tlsSelect != null && tlsSelect!="") {
			// protocols[0]="TLSv1.2";
			String[] protocols = new String[1];
			protocols[0] = tlsSelect;
			sslSocket.setEnabledProtocols(protocols);
		}
		if (cipherSelect != null && cipherSelect!="") {
			String[] ciphers = new String[1];
			// ciphers[0] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";			
			ciphers[0] = cipherSelect;
			sslSocket.setEnabledCipherSuites(ciphers);
		}
		return customizeSSLSocket(skt);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return factory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return factory.getSupportedCipherSuites();
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException, UnknownHostException {

		Socket skt = factory.createSocket(host, port);
		return customizeSSLSocket(skt);
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {

		Socket skt = factory.createSocket(host, port);
		return customizeSSLSocket(skt);
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {

		Socket skt = factory.createSocket(host, port, localHost, localPort);
		return customizeSSLSocket(skt);
	}

	@Override
	public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
			throws IOException {

		Socket skt = factory.createSocket(address, port, localAddress, localPort);
		return customizeSSLSocket(skt);
	}

	private Socket customizeSSLSocket(Socket skt) throws SocketException {
		((SSLSocket) skt).addHandshakeCompletedListener(new HandshakeCompletedListener() {
			public void handshakeCompleted(HandshakeCompletedEvent event) {
				LOGGER.debug("Handshake finished!");
				LOGGER.debug("\t CipherSuite:" + event.getCipherSuite());
				LOGGER.debug("\t SessionId " + event.getSession());
				LOGGER.debug("\t PeerHost " + event.getSession().getPeerHost());
				LOGGER.debug("\t PeerHost " + event.getSession().getProtocol());

			}
		});
		return skt;
	}

	public String[] getEnabledProtocols() {
		return enabledProtocols;
	}

	public void setEnabledProtocols(String[] enabledProtocols) {
		this.enabledProtocols = enabledProtocols;
	}

	public String[] getEnableCiphers() {
		return enableCiphers;
	}

	public void setEnableCiphers(String[] enableCiphers) {
		this.enableCiphers = enableCiphers;
	}
}
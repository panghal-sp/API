package com.newgen.ao.utility;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;

public class Services {

	static Logger xmlLog = Logger.getLogger("xmllog");
	NGCBSUploadConfig config = NGCBSUploadConfig.getInstance();


	public static class DummyTrustManager implements X509TrustManager {

		public DummyTrustManager() {
		}

		public boolean isClientTrusted(X509Certificate cert[]) {
			return true;
		}

		public boolean isServerTrusted(X509Certificate cert[]) {
			return true;
		}

		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}

		public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {

		}

		public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {

		}
	}

	public static class DummyHostnameVerifier implements HostnameVerifier {

		public boolean verify(String urlHostname, String certHostname) {
			return true;
		}

		public boolean verify(String arg0, SSLSession arg1) {
			return true;
		}

	}

	public String executeSecWebService(String uri, String requestbody) {
		StringBuilder content = new StringBuilder();
		/**
		 * Prod
		 */
		HttpsURLConnection conn = null;

		// HttpURLConnection conn=null;

		String isProxy = null;

		try {
			URL url = null;
			if (config.getProxyReq() == "Y") {
				Proxy proxy = new Proxy(Proxy.Type.HTTP,
						new InetSocketAddress(config.getProxyHost(), Integer.parseInt(config.getProxyPort())));
				xmlLog.info("Proxy Details -> " + config.getProxyHost() + " " + config.getProxyPort());
				url = new URL(uri);
				// conn = (HttpsURLConnection) url.openConnection(proxy);
				conn = (HttpsURLConnection) url.openConnection(proxy);
			} else {
				url = new URL(uri);
				conn = (HttpsURLConnection) url.openConnection();
			}

			SSLContext sslcontext = null;
			sslcontext = SSLContext.getInstance("SSL");

			sslcontext.init(new KeyManager[0], new TrustManager[] { new DummyTrustManager() }, new SecureRandom());
			SSLSocketFactory factory = sslcontext.getSocketFactory();

			conn.setDoOutput(true);
			conn.setRequestMethod("POST");

			conn.setRequestProperty("Content-Type", "application/xml");
			conn.setRequestProperty("Accept", "application/xml");
			conn.setConnectTimeout(99999);

			conn.setReadTimeout(99999);

			String token = Services.getToken();

			if (token.equals(null)) {
				return "Exception";
			}
			conn.setRequestProperty("Authorization", "Bearer " + token);

			/*
			 * connection.setRequestProperty(key, reqMap.get(key));
			 * 
			 * 
			 * connection.setRequestMethod(headObj.getRequest_method());
			 * 
			 * xmlLog1.info("Hitting End URL for Integration:"
			 * +integrationName+" with timeout of "+Integer.parseInt(headObj.getTime_out())
			 * +" ,ThreadName : "+Thread.currentThread().getName());
			 * 
			 * connection.setConnectTimeout(Integer.parseInt(headObj.getTime_out()));
			 * 
			 * 
			 * connection.setUseCaches(Boolean.parseBoolean(headObj.getUsecache()));
			 * 
			 * 
			 * connection.setDoOutput(Boolean.parseBoolean(headObj.getSetdooutput()));
			 * 
			 * 
			 * connection.setDoInput(Boolean.parseBoolean(headObj.getSetdoinput()));
			 * 
			 * 
			 * connection.setReadTimeout(Integer.parseInt(headObj.getR_timeout()));
			 */

			/**
			 * for prod
			 */
			conn.setSSLSocketFactory(factory);

			conn.setHostnameVerifier(new DummyHostnameVerifier());

			/*
			 * conn.setHostnameVerifier(new DummyHostnameVerifier()); if(uri == "") {
			 * Encoder bs= Base64.getEncoder(); String auth = config.getSMSUserName() + ":"
			 * + config.getSMSPassword(); byte[] encodedAuth =
			 * bs.encode(auth.getBytes(StandardCharsets.UTF_8)); String authHeaderValue =
			 * "Basic " + new String(encodedAuth); conn.setRequestProperty("Authorization",
			 * authHeaderValue); }
			 */
			if (requestbody.length() > 0) {
				byte[] buffer = new byte[requestbody.length()];
				buffer = requestbody.getBytes();
				ByteArrayOutputStream outStream = new ByteArrayOutputStream();
				outStream.write(buffer);
				byte[] inputByte = outStream.toByteArray();
				xmlLog.info("---------------inputByte Sec Web Service is " + inputByte.toString() + " ,ThreadName : "
						+ Thread.currentThread().getName());
				conn.setRequestProperty("Content-Length", String.valueOf(inputByte.length));
			}

			if (config.getProxyReq().equalsIgnoreCase("Y")) {
				Properties systemSettings = System.getProperties();
				systemSettings.put("proxySet", "true");
				systemSettings.put("https.proxyHost", config.getProxyHost());
				systemSettings.put("https.proxyPort", config.getProxyPort());
			}

			if (requestbody.length() > 0) {
				OutputStreamWriter out1 = new OutputStreamWriter(conn.getOutputStream());
				out1.write(requestbody);
				out1.close();
			}

			if (conn.getResponseCode() >= 400) {
				BufferedReader bufferedReade = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
				StringBuffer as=new StringBuffer(); 
				String lin;

				while ((lin = bufferedReade.readLine()) != null) {
					as.append(lin + "\n");
				}
				bufferedReade.close();
				xmlLog.info("Error Input Stream  Services :: "+as.toString());
				}
			
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;

			while ((line = bufferedReader.readLine()) != null) {
				content.append(line + "\n");
			}
			bufferedReader.close();
		} catch (Exception e) {
			xmlLog.info(" Error in Services Class  :" + e.getMessage());
			return "Exception";
		} finally {
			try {
				if (conn != null)
					conn.disconnect();
			} catch (Exception e1) {
				xmlLog.info(" Error :" + e1.getMessage());
			}
		}
		return content + "";
	}

	public static String getToken() {
		String query = "SELECT TOKEN FROM NG_EOBC_SMS_TOKEN_TABLE";

		xmlLog.info(" DB QUERY :: " + query);
		XMLParser parser = General.executeQuery(query);
		xmlLog.info("Output For DB QUERY :: " + parser);
		if (parser.getValueOf("MainCode").equals("0")) {
			xmlLog.info("##### query successfully executed  :: " + query + " ,ThreadName : "
					+ Thread.currentThread().getName());

			XMLParser sbParser = new XMLParser();
			// sbParser.setInputXML(query);

			// sbParser.setInputXML(parser.getValueOf("Record"));

			// for (int i = 0; i < parser.getNoOfFields("Record"); i++) {
			sbParser.setInputXML(parser.getValueOf("Record"));
			String token = sbParser.getValueOf("TOKEN");
			return token;
		}
		return null;
	}

}
package com.securitymanager.connection;


import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import java.util.HashMap;
import java.util.Iterator;



public class KeyManager {
	private String clientToken="";
	private String vaultIP;
	private String port;
	private String jssecacertPath;
	private String keystorePath;
	private String keyPassword;
	private String backendPath;
	private PropertyValues propertyValues;
	private String apiURL;
	private String baseURL="https://";
	private String version="/v1/";
	private String path;
	private int statusCode;
	private String vaultTokenHeader="X-Vault-Token";
	private Logger logger = LoggerFactory.getLogger(KeyManager.class);
	private HttpClient client;
	private HttpGet getRequest;
	private HttpResponse responseStmt;
	private StatusLine responseString;
	private BufferedReader bufferedReader;
	private StringBuilder response;
	private String lineReader;
	private JSONObject responseObject ;
	private URL url;
	private HttpsURLConnection con;
	private KeyManagerFactory keyManagerFactory;
	private KeyStore keyStore;
	private InputStream keyInput;
	private SSLContext context ;
	private  InputStream inputStream;
	private String flag;


	public  KeyManager() throws KeyManagerConnectionException{
		propertyValues=new PropertyValues();
		this.vaultIP=propertyValues.getVaultIP();
		this.port=propertyValues.getPort();
		this.jssecacertPath=propertyValues.getJssecacerPath();
		this.keystorePath=propertyValues.getKeystorePath();
		this.keyPassword=propertyValues.getKeyPassword();
		this.backendPath=propertyValues.getBackendPath();
		this.flag=propertyValues.getFlag();
	}


	public  KeyManager(String envVariable) throws KeyManagerConnectionException{
		propertyValues=new PropertyValues(envVariable);
		this.vaultIP=propertyValues.getVaultIP();
		this.port=propertyValues.getPort();
		this.jssecacertPath=propertyValues.getJssecacerPath();
		this.keystorePath=propertyValues.getKeystorePath();
		this.keyPassword=propertyValues.getKeyPassword();
		this.backendPath=propertyValues.getBackendPath();
		this.flag=propertyValues.getFlag();
	}


	

	public void authenticate()throws KeyManagerConnectionException, IOException{
		if(flag.equals("0")){
			Properties systemProps = System.getProperties();
			systemProps.put( "javax.net.ssl.trustStore", jssecacertPath);
			System.setProperties(systemProps);
			path = "auth/cert/login";
			apiURL =  baseURL  + vaultIP + ":" + port + version +  path ;
			// Open a secure connection.  
			try {
				url = new URL(apiURL );
			} catch (MalformedURLException e1) {
				// TODO Auto-generated catch block
				logger.error("URL error", e1);
			}

			try {
				con = (HttpsURLConnection) url.openConnection();
				con.setRequestProperty( "Connection", "close" );
				con.setDoInput(true);
				con.setDoOutput(true);
				con.setUseCaches(false);
				con.setRequestMethod( "POST" );
				con.setRequestProperty( "Content-Type", "application/x-www-form-urlencoded" );
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				logger.error("IOException", e1);
			}
			// Set up the connection properties  
			File pKeyFile = new File(keystorePath);

			try {
				keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
				keyStore = KeyStore.getInstance("PKCS12");
				keyInput = new FileInputStream(pKeyFile);
				keyStore.load(keyInput, keyPassword.toCharArray());
				keyInput.close();
				keyManagerFactory.init(keyStore, keyPassword.toCharArray());
				context = SSLContext.getInstance("TLS");
				context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
			} catch (NoSuchAlgorithmException e) {
				logger.error("NoSuchAlgorithException", e);
			} catch (KeyStoreException e) {
				logger.error("KeyStoreException", e);
			} catch (CertificateException e) {
				logger.error("CerificateException", e);
			} catch (UnrecoverableKeyException e) {
				logger.error("UnrecoverableKeyException", e);
			} catch (KeyManagementException e) {
				logger.error("KeyManagementException",e);
			}

			SSLSocketFactory sockFact = context.getSocketFactory();
			con.setSSLSocketFactory( sockFact );

			try {
				statusCode = con.getResponseCode();
			} catch (IOException e1) {
				logger.error("IOException", e1);
			}

			if (statusCode == HttpURLConnection.HTTP_OK) {
				logger.info("[VAULT AUTHENTICATED]");
				try {
					inputStream = con.getInputStream();
				} catch (IOException e1) {
					logger.error("IOException", e1);
				}
				// Process the response

				String line = null;
				response = null;
				response = new StringBuilder();
				bufferedReader = new BufferedReader( new InputStreamReader( inputStream ) );
				while( ( line = bufferedReader.readLine() ) != null )
				{
					response.append(line);
				}

				try {
					inputStream.close();
				} catch (IOException e1) {
					logger.error("IOException", e1);
				}
				
				try {
					responseObject = new JSONObject(response.toString());
					clientToken=responseObject.getJSONObject("auth").getString("client_token");
				} catch (JSONException e) {
					logger.error("JSON Exception error", e);
				}

			} else {
				throw new KeyManagerConnectionException(statusCode);
			}

		}

	}


	public HashMap<String,String> getCredentials()throws KeyManagerConnectionException,IOException{

		HashMap<String, String> keyValue = new HashMap<String, String>();
		
		if(flag.equals("0")){
			apiURL = baseURL + vaultIP + ":" + port + version + backendPath ;
			client = HttpClientBuilder.create().build();
			getRequest = new HttpGet(apiURL);
			getRequest.addHeader(vaultTokenHeader, clientToken);
			responseStmt = client.execute(getRequest);
			responseString=responseStmt.getStatusLine();
			statusCode=responseString.getStatusCode();
			if(statusCode == 200){
				logger.info("[PATH VALID]");
				bufferedReader = new BufferedReader(new InputStreamReader(responseStmt.getEntity().getContent()));
				lineReader = null;
				response = new StringBuilder();
				while ((lineReader = bufferedReader.readLine()) != null) {
					response.append(lineReader);
				}

				try {
					JSONObject responseJson = new JSONObject(response.toString());
					JSONObject dataJson = responseJson.getJSONObject("data");
					Iterator<?> iterator = dataJson.keys();
					while(iterator.hasNext()){
						String key = (String)iterator.next();
						String value = dataJson.getString(key);
						keyValue.put(key,value);
					}
					return keyValue;

				} catch (JSONException e) {
					// TODO Auto-generated catch block
					logger.error("JSON Exception error", e);
				}

			}
			else{
				throw new KeyManagerConnectionException(statusCode);
			}

			
		}
		else{
			keyValue=propertyValues.getKeyValue();
		}
		return keyValue;
	}
	
	
}
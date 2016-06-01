package com.securitymanager.appid;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.securitymanager.connection.KeyManagerConnectionException;
import com.securitymanager.connection.PropertyValues;

public class AppidManager {
	
	private String clientToken="";
	private String vaultIP;
	private String port;
	private String jssecacertPath;
	private String backendPath;
	private PropertyValues propertyValues;
	private String apiURL;
	private String baseURL="https://";
	private String version="/v1/";
	private String path;
	private int statusCode;
	private String vaultTokenHeader="X-Vault-Token";
	private Logger logger = LoggerFactory.getLogger(AppidManager.class);
	private HttpClient client;
	private HttpPost postRequest;
	private HttpGet getRequest;
	private HttpResponse responseStmt;
	private StatusLine responseString;
	private BufferedReader bufferedReader;
	private StringBuilder response;
	private String lineReader;
	private String flag;
	private String organisation;
	private String component;
	private String service;
	private HashString hashtheValue;
	private String appport;
	private String appname;
	
	public AppidManager() throws KeyManagerConnectionException{
		propertyValues=new PropertyValues();
		this.vaultIP=propertyValues.getVaultIP();
		this.port=propertyValues.getPort();
		this.jssecacertPath=propertyValues.getJssecacerPath();
		this.backendPath=propertyValues.getBackendPath();
		this.organisation=propertyValues.getOrganisation();
		this.component=propertyValues.getComponent();
		this.service=propertyValues.getService();
		this.flag=propertyValues.getFlag();
		this.appname=propertyValues.getAppname();
		this.appport=propertyValues.getAppport();
		this.backendPath=propertyValues.getBackendPath();
		hashtheValue=new HashString();
		Properties systemProps = System.getProperties();
		systemProps.put( "javax.net.ssl.trustStore", jssecacertPath);
		System.setProperties(systemProps);
	}
	
	public void authenticate()throws KeyManagerConnectionException, IOException, NoSuchAlgorithmException{
		
		client = HttpClientBuilder.create().build();
		if(flag.equals("0")){
			path = "auth/app-id/login";
			apiURL =  baseURL  + vaultIP + ":" + port + version +  path ;
			StringBuilder servicename = new StringBuilder();
			servicename.append(organisation).append(component).append(service);
			InetAddress ipAddr = InetAddress.getLocalHost();
			String appid=hashtheValue.makeSHA1Hash(servicename.toString());
			String userid=hashtheValue.makeSHA1Hash(ipAddr.getHostAddress()+appname+appport);
			logger.info("appid:"+appid);
			logger.info("userid:"+userid);
			try
			{
				
				postRequest = new HttpPost(apiURL);
				StringEntity appiduserid = new StringEntity("{\"app_id\":\""+appid+"\", \"user_id\": \""+userid+"\"}" ,"UTF-8");
				appiduserid.setContentType("application/json");
				postRequest.setEntity(appiduserid);
				responseStmt = client.execute(postRequest);
				StatusLine statusLine = responseStmt.getStatusLine();
				int statusCode = statusLine.getStatusCode();
				
				if(statusCode/100==3){
					apiURL= responseStmt.getFirstHeader("Location").getValue();
					postRequest = new HttpPost(apiURL);
					postRequest.setEntity(appiduserid);
					responseStmt = client.execute(postRequest);
					statusLine = responseStmt.getStatusLine();
					statusCode = statusLine.getStatusCode();
				}
				
				if(statusCode==200)
				{
					BufferedReader breader = new BufferedReader(new InputStreamReader(responseStmt.getEntity().getContent()));
					String line;
					response = new StringBuilder();
					while( (line = breader.readLine() ) != null )
					{
						response.append(line);
					}
					try {
						JSONObject responseObject = new JSONObject(response.toString());
						clientToken=responseObject.getJSONObject("auth").getString("client_token");
					} catch (JSONException e) {
						logger.error("JSON Exception error", e);
					} 
				}
				else
				{
					logger.error("User not authenticated in vault:"+statusCode);
				}
			}
			catch(Exception e)
			{
				logger.error("Exception occured",e);
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

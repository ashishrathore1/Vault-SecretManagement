package com.securitymanager.connection;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PropertyValues {

	public InputStream inputStream;
	public Properties properties;
	public String vaultIP;
	public String port;
	public String username;
	public String password;
	public String keyPassword;
	public String organisation;
	public String component;
	public String service;

	public String appip;
	public String appport;
	public String appname;
	
	public HashMap<String, String> keyValue;
	private Logger logger = LoggerFactory.getLogger(PropertyValues.class);
	public PropertyValues() {
		// TODO Auto-generated constructor stub
		try {
			properties = new Properties();
			String propertyFileName = "vault.properties";  //mandatory name 'config.properties'
			inputStream = getClass().getClassLoader().getResourceAsStream(propertyFileName);
			if (inputStream != null) {
				properties.load(inputStream);

			} else {
				throw new FileNotFoundException("Property file '" + propertyFileName + "' not found in the classpath");
			}

		} catch (Exception e) {
			logger.error("Property values error", e);
		} 

	}


	public PropertyValues(String envVariable) {
		// TODO Auto-generated constructor stub
		try {
			properties = new Properties();
			String propertyFileName = System.getenv(envVariable)+"/vault.properties";  //mandatory name 'config.properties'
			inputStream = getClass().getResourceAsStream(propertyFileName);
			properties.load(new FileInputStream(propertyFileName));
		} catch (Exception e) {
			logger.error("Property values error", e);
		} 

	}



	public String getAppport() {
		return properties.getProperty("appid.port");
	}


	public String getAppname() {
		return properties.getProperty("appid.hostname");
	}


	public String getOrganisation() {
		return properties.getProperty("appid.organisation");
	}


	public String getComponent() {
		return properties.getProperty("appid.component");
	}


	public String getService() {
		return properties.getProperty("appid.service");
	}


	public String getVaultIP() {
		return properties.getProperty("vault.ip");
	}

	public String getPort() {
		return properties.getProperty("vault.port");
	}

	public String getJssecacerPath() throws KeyManagerConnectionException {
		String jssecacertPath=properties.getProperty("vault.jssecacertPath");
		if(jssecacertPath.length()>=200){
			int status_code=420;
			throw new KeyManagerConnectionException(status_code);
		}
		else{
			return properties.getProperty("vault.jssecacertPath");
		}
	}

	public String getKeystorePath() throws KeyManagerConnectionException {
		String keystorePath=properties.getProperty("vault.keystorePath");
		String substr=keystorePath.substring(keystorePath.length()-4,keystorePath.length());
		if(keystorePath.length()>=200){
			int status_code=420;
			throw new KeyManagerConnectionException(status_code);
		}
		else if(!substr.equals(".p12")){
			int status_code=421;
			throw new KeyManagerConnectionException(status_code);
		}
		else{
			return keystorePath;}
	}

	public String getKeyPassword(){
		return properties.getProperty("vault.keyPassword");	
	}


	public String getFlag() {
		// TODO Auto-generated method stub
		return properties.getProperty("vault.disable");
	}

	public String getBackendPath() throws KeyManagerConnectionException {
		// TODO Auto-generated method stub
		String backendPath=properties.getProperty("vault.backendPath");
		if(backendPath.length()>=200){
			int status_code=420;
			throw new KeyManagerConnectionException(status_code);
		}
		else{
			return properties.getProperty("vault.backendPath");}
	}

	public HashMap<String, String>getKeyValue(){
		Enumeration<Object> e = properties.keys();
		keyValue = new HashMap<String, String>();
		while (e.hasMoreElements()) {
			String key = (String) e.nextElement();
			String value = properties.getProperty(key);
			keyValue.put(key, value);
		}
		return keyValue;
	}


}

package com.securitymanager.connection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("serial")
 public class KeyManagerConnectionException extends Exception {

	private int status_code;
	private Logger logger = LoggerFactory.getLogger(KeyManagerConnectionException.class);
	public KeyManagerConnectionException(int status_code){
		super();
		this.status_code = status_code;
		if(status_code==420){	
	    	logger.error(status_code+" Path is too long.");	
	    }
		else if(status_code==421){	
	    	logger.error(status_code+" Not a valid client certificate");	
	    }
		else if(status_code==400){	
	    	logger.error(status_code+" Invalid request, missing or invalid data");	
	    }
	    else if(status_code==401){
	    	logger.error(status_code+" Unauthorized, your authentication details are either incorrect or you don't have access to this feature.");
	    }
	    else if(status_code==403){
	    	logger.error(status_code+" This vault is not accessible to you");
	    }
	    else if(status_code==404){
	    	logger.error(status_code+" Invalid path");
	    }
	    else if(status_code==429){
	    	logger.error(status_code+" Rate limit exceeded");
	    }
	    else if(status_code==500){
	    	logger.error(status_code+" Invalid request, missing or invalid data");
	    }
	    else if(status_code==503){
	    	logger.error(status_code+" Vault is down for maintenance or is currently sealed. Try again later.");
	    }
	    else{
	    	logger.error(status_code+" Some KeyManagerConnectionException occured ");
	    }
		
	}

	@Override
	public String toString() {
		//System.out.println("Error in making connection");    
		return "KeyManagerConnectionException [status_code=" + status_code + "]";
	}	

	
}



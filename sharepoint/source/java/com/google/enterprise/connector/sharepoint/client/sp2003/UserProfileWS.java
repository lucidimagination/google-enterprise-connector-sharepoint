package com.google.enterprise.connector.sharepoint.client.sp2003;

import java.rmi.RemoteException;
import java.text.Collator;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.rpc.ServiceException;

import org.apache.axis.AxisFault;
import org.apache.catalina.util.URLEncoder;

import com.google.enterprise.connector.sharepoint.SharepointConnectorType;
import com.google.enterprise.connector.sharepoint.client.SharepointClientContext;
import com.google.enterprise.connector.sharepoint.client.SharepointException;
import com.google.enterprise.connector.sharepoint.client.WebsWS;
import com.google.enterprise.connector.sharepoint.generated.sp2003.userprofileservice.GetUserProfileByIndexResult;
import com.google.enterprise.connector.sharepoint.generated.sp2003.userprofileservice.PropertyData;
import com.google.enterprise.connector.sharepoint.generated.sp2003.userprofileservice.UserProfileService;
import com.google.enterprise.connector.sharepoint.generated.sp2003.userprofileservice.UserProfileServiceLocator;
import com.google.enterprise.connector.sharepoint.generated.sp2003.userprofileservice.UserProfileServiceSoap_BindingStub;

/**
 * @author amit_kagrawal
 * This class holds data and methods for any call to UserProfile Web Service.
 * */
public class UserProfileWS {
	private static final String USERPROFILEENDPOINT = "_vti_bin/UserProfileService.asmx";
	private static final Logger LOGGER = Logger.getLogger(UserProfileWS.class.getName());
	private String className = WebsWS.class.getName();
	private SharepointClientContext sharepointClientContext;
//	private UserProfileServiceSoapStub stub;
	private UserProfileServiceSoap_BindingStub stub;
	static final String URL_SEP ="://";
	private static final String SLASH = "/";
	
	public static String personalSpaceTag = "PersonalSpace";
	public static URLEncoder enc  = new URLEncoder();
	  
	  static{
			//set the URLEncoder safe characters
			enc.addSafeCharacter('/');
			enc.addSafeCharacter(':');// required when endpoint is set using specified site
		}
	public UserProfileWS(SharepointClientContext inSharepointClientContext){
		String sFunctionName = "UserProfileWS(SharepointClientContext inSharepointClientContext)";
		LOGGER.entering(className, sFunctionName);
		if(inSharepointClientContext!=null){
			this.sharepointClientContext = inSharepointClientContext;
			String endpoint = inSharepointClientContext.getProtocol()+URL_SEP + inSharepointClientContext.getHost() + ":" +inSharepointClientContext.getPort() + /*Util.getEscapedSiteName(*/enc.encode(inSharepointClientContext.getsiteName())/*)*/
    		+ SLASH+USERPROFILEENDPOINT;
			
//			System.out.println("UProfileEndPt: "+endpoint);
			UserProfileServiceLocator loc = new UserProfileServiceLocator();
			loc.setUserProfileServiceSoapEndpointAddress(endpoint);
			
			UserProfileService service = loc;
			try {
				stub = (UserProfileServiceSoap_BindingStub) service.getUserProfileServiceSoap();
			} catch (ServiceException e) {
				e.printStackTrace();
			}	
			
			//get the credentials
			String strDomain = inSharepointClientContext.getDomain();
			String strUserName = inSharepointClientContext.getUsername();
			strDomain+="\\"+strUserName;
			String strPassword = inSharepointClientContext.getPassword();
			
			//set authentication
			stub.setUsername(strDomain);
			stub.setPassword(strPassword);
		}
		LOGGER.exiting(className, sFunctionName);
	}
	
	

	public boolean isSPS() throws SharepointException{
		String sFunctionName = "isSPS()";
		LOGGER.entering(className, sFunctionName);
		if(stub==null){
			throw new SharepointException("UserProfile stub not found");
		}
		try{
	        stub.getUserProfileByIndex(0);
	        LOGGER.info("SPS site");
	        LOGGER.exiting(className, sFunctionName);
	        return true;
        }catch(AxisFault fault){
        	LOGGER.info("WSS site");
        	LOGGER.exiting(className, sFunctionName);
	        return false;
        } catch (Exception e) {
        	 LOGGER.warning(sFunctionName+" : "+e);
        	 return false;
		}
        
	}
	
	public List getPersonalSiteList() throws SharepointException {
		final String sFunctionName ="getPersonalSiteList()";
		LOGGER.entering(className, sFunctionName);
		ArrayList lstAllPersonalSites = new ArrayList(); //list of personal sites and subsites
		Collator collator = SharepointConnectorType.getCollator();
		if(stub==null){
	    	throw new SharepointException(sFunctionName+": Unable to get the userprofile stub");
	    }

	    int index = 0;
	    while (index >= 0) {
	     
		 GetUserProfileByIndexResult result = null;
		try {
			
			result = stub.getUserProfileByIndex(index);
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	      if (result == null || result.getUserProfile() == null) {
	        break;
	      }
	      
	      PropertyData[] data= result.getUserProfile();
	      if (data == null) {
	        break;
	      }
	      
	      
	      String /*acct = null,*/ space = null;
	      for (int i = 0; i < data.length; ++i) {
	        String name = data[i].getName();
	        if (collator.equals(personalSpaceTag,name)) {
	        	String PropVal = data[i].getValue();//e.g. /personal/administrator/
	        	if (PropVal == null) {
		            continue;
		          }
	        	String sharepointURL = sharepointClientContext.getProtocol()+URL_SEP+sharepointClientContext.getHost()+":"+sharepointClientContext.getPort()+sharepointClientContext.getsiteName();
//		          System.out.println("BaseSite: "+sharepointURL);
		          String strURL = sharepointURL+PropVal;
		          
//	          System.out.println("Personal: "+strURL);
	          if (strURL.endsWith("/")) {
	        	  strURL = strURL.substring(
	  					0, strURL.lastIndexOf("/"));
	  			}
	          lstAllPersonalSites.add(strURL);
	          
	        }
	      }
	      if (space == null) {
	        break;
	      }
	      String next = result.getNextValue();
	      index = Integer.parseInt(next);
	    }
	    LOGGER.exiting(className, sFunctionName);
	    if(lstAllPersonalSites!=null){
	    	LOGGER.info("Total personal sites returned: "+lstAllPersonalSites.size());
	    }
		return lstAllPersonalSites;
	 }
	
}

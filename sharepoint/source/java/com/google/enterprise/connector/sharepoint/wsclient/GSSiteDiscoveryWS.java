//Copyright 2007 Google Inc.

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at

//http://www.apache.org/licenses/LICENSE-2.0

//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

package com.google.enterprise.connector.sharepoint.wsclient;

import com.google.enterprise.connector.sharepoint.client.SPConstants;
import com.google.enterprise.connector.sharepoint.client.SharepointClientContext;
import com.google.enterprise.connector.sharepoint.client.Util;
import com.google.enterprise.connector.sharepoint.generated.gssitediscovery.ListCrawlInfo;
import com.google.enterprise.connector.sharepoint.generated.gssitediscovery.SiteDiscovery;
import com.google.enterprise.connector.sharepoint.generated.gssitediscovery.SiteDiscoveryLocator;
import com.google.enterprise.connector.sharepoint.generated.gssitediscovery.SiteDiscoverySoap_BindingStub;
import com.google.enterprise.connector.sharepoint.generated.gssitediscovery.WebCrawlInfo;
import com.google.enterprise.connector.sharepoint.spiimpl.SharepointException;
import com.google.enterprise.connector.sharepoint.state.ListState;
import com.google.enterprise.connector.sharepoint.state.WebState;

import com.google.enterprise.connector.sharepoint.generated.sitedata.SiteData;
import com.google.enterprise.connector.sharepoint.generated.sitedata.SiteDataLocator;
import com.google.enterprise.connector.sharepoint.generated.sitedata.SiteDataSoap_BindingStub;

import com.google.enterprise.connector.sharepoint.generated.webs.Webs;
import com.google.enterprise.connector.sharepoint.generated.webs.WebsLocator;
import com.google.enterprise.connector.sharepoint.generated.webs.WebsSoap_BindingStub;


import org.apache.axis.AxisFault;
import org.apache.axis.message.MessageElement;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.rpc.ServiceException;

/**
 * Java Client for calling GSSiteDiscovery.asmx. Provides a layer to talk to the
 * GSSiteDiscovery Web Service deployed on the SharePoint server Any call to
 * this Web Service must go through this layer.
 *
 * @author nitendra_thakur
 */
public class GSSiteDiscoveryWS {
  private static final Logger LOGGER = Logger.getLogger(GSSiteDiscoveryWS.class.getName());
  private SharepointClientContext sharepointClientContext;
  private String endpoint;
  private SiteDiscoverySoap_BindingStub stub = null;
  private String endpoint_webs;
  private String endpoint_siteData;
  private WebsSoap_BindingStub stub_webs = null;
  private SiteDataSoap_BindingStub stub_siteData = null;
  
  /**
   * @param inSharepointClientContext The Context is passed so that necessary
   *          information can be used to create the instance of current class
   *          Web Service endpoint is set to the default SharePoint URL stored
   *          in SharePointClientContext.
   * @throws SharepointException
   */
  
	public static boolean getNoIndexFromContent(String xmlString)
			throws SAXException, IOException, ParserConfigurationException {
		org.w3c.dom.Document XMLDoc = DocumentBuilderFactory.newInstance()
				.newDocumentBuilder()
				.parse(new InputSource(new StringReader(xmlString)));
		org.w3c.dom.Element element = XMLDoc.getDocumentElement();
		return Boolean.parseBoolean(((org.w3c.dom.Element) element
				.getFirstChild()).getAttribute("NoIndex"));
	}
	
	public Object[] getUrlsFromMessage(MessageElement[] elements) {
		List<Object> objects = new ArrayList<Object>();
		for (MessageElement child : elements) {
			for (final java.util.Iterator itrchild = child.getChildElements(); itrchild
					.hasNext();) {
				MessageElement oneAttr = (MessageElement) itrchild.next();//
				if (oneAttr != null)
					objects.add(oneAttr.getAttribute("Url"));
			}
		}
		return objects.toArray();
	}
	  
  public GSSiteDiscoveryWS(
      final SharepointClientContext inSharepointClientContext, String siteUrl)
      throws SharepointException {
    if (inSharepointClientContext != null) {
      sharepointClientContext = inSharepointClientContext;
      if (null == siteUrl) {
        siteUrl = sharepointClientContext.getSiteURL();
      }
      endpoint = Util.encodeURL(siteUrl)
          + SPConstants.GSPSITEDISCOVERYWS_END_POINT;
      LOGGER.log(Level.CONFIG, "Endpoint set to: " + endpoint);

      endpoint_webs = Util.encodeURL(siteUrl)
              + SPConstants.WEBSENDPOINT;
      LOGGER.log(Level.CONFIG, "Endpoint for webs set to: " + endpoint);

      endpoint_siteData = Util.encodeURL(siteUrl)
              + SPConstants.SITEDATAENDPOINT;
      LOGGER.log(Level.CONFIG, "Endpoint for siteData set to: " + endpoint);

      final SiteDiscoveryLocator loc = new SiteDiscoveryLocator();
      loc.setSiteDiscoverySoapEndpointAddress(endpoint);
      final SiteDiscovery gspSiteDiscovery = loc;
      
      final WebsLocator loc_webs = new WebsLocator();
      loc_webs.setWebsSoapEndpointAddress(endpoint_webs);
      final Webs gspWebs = loc_webs;
      
      final SiteDataLocator loc_siteData = new SiteDataLocator();
      loc_siteData.setSiteDataSoapEndpointAddress(endpoint_siteData);
      final SiteData gspSiteData = loc_siteData;

      try {
        stub = (SiteDiscoverySoap_BindingStub) gspSiteDiscovery.getSiteDiscoverySoap();
      } catch (final ServiceException e) {
        LOGGER.log(Level.WARNING, e.getMessage(), e);
        sharepointClientContext.setEnabledGoogleServices(false);
        throw new SharepointException("Unable to get the GSSiteDiscovery stub");
      }
      
      if(!sharepointClientContext.isEnabledGoogleServices()){
       try {
          stub_siteData = (SiteDataSoap_BindingStub)gspSiteData.getSiteDataSoap();
       } catch (final ServiceException e) {
              LOGGER.log(Level.WARNING, e.getMessage(), e);
              throw new SharepointException("Unable to get the stub_siteData stub");
       }
          
       try {
          stub_webs = (WebsSoap_BindingStub) gspWebs.getWebsSoap();
       }catch (final ServiceException e) {
              LOGGER.log(Level.WARNING, e.getMessage(), e);
              throw new SharepointException("Unable to get the stub_webs stub");
       }
      }

      final String strDomain = inSharepointClientContext.getDomain();
      String strUser = inSharepointClientContext.getUsername();
      final String strPassword = inSharepointClientContext.getPassword();

      strUser = Util.getUserNameWithDomain(strUser, strDomain);
      stub.setUsername(strUser);
      stub.setPassword(strPassword);
      // The web service time-out value
      stub.setTimeout(sharepointClientContext.getWebServiceTimeOut());
      
	  if (!sharepointClientContext.isEnabledGoogleServices()) {
		stub_webs.setUsername(strUser);
		stub_webs.setPassword(strPassword);
		// The web service time-out value
		stub_webs.setTimeout(sharepointClientContext
				.getWebServiceTimeOut());
		stub_siteData.setUsername(strUser);
		stub_siteData.setPassword(strPassword);
		// The web service time-out value
		stub_siteData.setTimeout(sharepointClientContext
				.getWebServiceTimeOut());
	  }
      LOGGER.fine("Set time-out of : "
          + sharepointClientContext.getWebServiceTimeOut() + " milliseconds");
    }
  }

  /**
   * Gets all the sitecollections from all the web applications for a given
   * sharepoint installation
   *
   * @return the set of all site colelltions returned bu the GSSiteDiscovery
   */
  

  public Object[] getSiteCollectionsWithGoogleServices(){
      try {
  	      return stub.getAllSiteCollectionFromAllWebApps();
  	    } catch (final AxisFault af) { // Handling of username formats for
  	      // different authentication models.
  	      if ((SPConstants.UNAUTHORIZED.indexOf(af.getFaultString()) != -1)
  	          && (sharepointClientContext.getDomain() != null)) {
  	        final String username = Util.switchUserNameFormat(stub.getUsername());
  	        LOGGER.log(Level.CONFIG, "Web Service call failed for username [ "
  	            + stub.getUsername() + " ]. Trying with " + username);
  	        stub.setUsername(username);
  	        try {
  	        	return  stub.getAllSiteCollectionFromAllWebApps();
  	        } catch (final Exception e) {
  	          LOGGER.log(Level.WARNING, "Call to the GSSiteDiscovery web service failed with the following exception: ", e);
  	          return null;
  	        }
  	      } else {
  	        LOGGER.log(Level.WARNING, "Call to the GSSiteDiscovery web service failed with the following exception: ", af);
  	        return null;
  	      }
  	    } catch (final Throwable e) {
  	      LOGGER.log(Level.WARNING, "Call to the GSSiteDiscovery web service failed with the following exception: ", e);
  	      return null;
  	    }	

  }

  public Object[] getSiteCollectionsWithoutGoogleServices() {
      try {
  	      return getUrlsFromMessage(stub_webs.getAllSubWebCollection().get_any());
  	    } catch (final AxisFault af) { // Handling of username formats for
  	      // different authentication models.
  	      if ((SPConstants.UNAUTHORIZED.indexOf(af.getFaultString()) != -1)
  	          && (sharepointClientContext.getDomain() != null)) {
  	        final String username = Util.switchUserNameFormat(stub_webs.getUsername());
  	        LOGGER.log(Level.CONFIG, "Web Service call failed for username [ "
  	            + stub_webs.getUsername() + " ]. Trying with " + username);
  	        stub_webs.setUsername(username);
  	        try {
  	        	return getUrlsFromMessage(stub_webs.getAllSubWebCollection().get_any());
  	        } catch (final Exception e) {
  	          LOGGER.log(Level.WARNING, "Call to the webs web service failed with the following exception: ", e);
  	          return null;
  	        }
  	      } else {
  	        LOGGER.log(Level.WARNING, "Call to the webs web service failed with the following exception: ", af);
  	        return null;
  	      }
  	    } catch (final Throwable e) {
  	      LOGGER.log(Level.WARNING, "Call to the webs web service failed with the following exception: ", e);
  	      return null;
  	    }	

  }
    
    public Set<String> getMatchingSiteCollections() {
  	    final Set<String> siteCollections = new TreeSet<String>();
  	    Object[] res = null;
		if (sharepointClientContext.isEnabledGoogleServices())
			res = getSiteCollectionsWithGoogleServices();
		else
			res = getSiteCollectionsWithoutGoogleServices();
  	    if (null != res) {
  	      for (Object element : res) {
  	        String url = (String) element;
  	        URL u = null;
  	        try {
  	          u = new URL(url);
  	        } catch (final MalformedURLException e1) {
  	          LOGGER.log(Level.WARNING, "Malformed site collection URL found [ "
  	              + url + " ]", e1);
  	          continue;
  	        }

  	        int iPort = u.getPort();
  	        if (iPort == -1) {
  	          iPort = u.getDefaultPort();
  	        }

  	        url = u.getProtocol() + SPConstants.URL_SEP + getFQDNHost(u.getHost())
  	            + SPConstants.COLON + iPort;

  	        final String path = u.getPath();
  	        if ((path == null) || path.equalsIgnoreCase("")) {
  	          url += SPConstants.SLASH;
  	        } else {
  	          url += path;
  	        }

  	        if (sharepointClientContext.isIncludedUrl(url)) {
  	          siteCollections.add(url);
  	        } else {
  	          LOGGER.warning("excluding " + url);
  	        }
  	      }
  	    }
  	    LOGGER.log(Level.CONFIG, "GSSiteDiscovery discovered following Site Collection URLs:"
  	        + siteCollections);
  	    return siteCollections;
  	  }


  /**
   * @param hostName
   * @return the the host in FQDN format
   */
  public String getFQDNHost(final String hostName) {
    if (sharepointClientContext.isFQDNConversion()) {
      InetAddress ia = null;
      try {
        ia = InetAddress.getByName(hostName);
      } catch (final UnknownHostException e) {
        LOGGER.log(Level.WARNING, "Host cannot be identified [ " + hostName
            + " ]", e);
      }
      if (ia != null) {
        return ia.getCanonicalHostName();
      }
    }
    return hostName;
  }

  /**
   * Retrieves the information about crawl behavior of the web whose URL was
   * used to construct the endpoint
   *
   * @return WebCrawlInfo of the web whose URL was used to construct the
   *         endpoint
   */
  
  public WebCrawlInfo getCurrentWebCrawlInfo() {
		if (sharepointClientContext.isEnabledGoogleServices())
			return getCurrentWebCrawlInfoWithGoogleServices();
		else
			return getCurrentWebCrawlInfoWithoutGoogleServices();
  }
  
  public WebCrawlInfo getCurrentWebCrawlInfoWithGoogleServices() {
    try {
      LOGGER.config("Fetching SharePoint indexing options for site : "
          + sharepointClientContext.getSiteURL());
      return stub.getWebCrawlInfo();
    } catch (final AxisFault af) {
      if ((SPConstants.UNAUTHORIZED.indexOf(af.getFaultString()) != -1)
          && (sharepointClientContext.getDomain() != null)) {
        final String username = Util.switchUserNameFormat(stub.getUsername());
        LOGGER.log(Level.CONFIG, "Web Service call failed for username [ "
            + stub.getUsername() + " ]. Trying with " + username);
        stub.setUsername(username);
        try {
          return stub.getWebCrawlInfo();
        } catch (final Exception e) {
          LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.GetWebCrawlInfo() failed with the following exception: ", e);
        }
      } else {
        LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.GetWebCrawlInfo() failed with the following exception: ", af);
      }
    } catch (final Throwable e) {
      LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.GetWebCrawlInfo() failed with the following exception: ", e);
    }
    return null;
  }
  
  
  public WebCrawlInfo getCurrentWebCrawlInfoWithoutGoogleServices() {
		javax.xml.rpc.holders.StringHolder lastChangeID = new javax.xml.rpc.holders.StringHolder();
	    try {
			LOGGER.config("Fetching SharePoint indexing options for site : "
					+ sharepointClientContext.getSiteURL());
			String result = stub_siteData
					.getContent(
							com.google.enterprise.connector.sharepoint.generated.sitedata.ObjectType
									.fromString("Site"), "", "", "", true,
							true, lastChangeID);
			boolean nocrawl = getNoIndexFromContent(result);
			return new WebCrawlInfo(sharepointClientContext.getSiteURL(), true,
					getNoIndexFromContent(result), true, "");
	    } catch (final AxisFault af) {
	      if ((SPConstants.UNAUTHORIZED.indexOf(af.getFaultString()) != -1)
	          && (sharepointClientContext.getDomain() != null)) {
	        final String username = Util.switchUserNameFormat(stub_siteData.getUsername());
	        LOGGER.log(Level.CONFIG, "Web Service call failed for username [ "
	            + stub_siteData.getUsername() + " ]. Trying with " + username);
	        stub_siteData.setUsername(username);
	        try {
					String result = stub_siteData
							.getContent(
									com.google.enterprise.connector.sharepoint.generated.sitedata.ObjectType
											.fromString("Site"), "", "", "",
									true, true, lastChangeID);
					boolean nocrawl = getNoIndexFromContent(result);
					return new WebCrawlInfo(
							sharepointClientContext.getSiteURL(), true,
							nocrawl, true, "");
	          } catch (final Exception e) {
	            LOGGER.log(Level.WARNING, "Call to siteData.getCurrentWebCrawlInfoWithoutGoogleServices() failed with the following exception: ", e);
	          }
	      } else {
	        LOGGER.log(Level.WARNING, "Call to siteData.getCurrentWebCrawlInfoWithoutGoogleServices() failed with the following exception: ", af);
	      }
	    } catch (final Throwable e) {
	      LOGGER.log(Level.WARNING, "Call to siteData.getCurrentWebCrawlInfoWithoutGoogleServices() failed with the following exception: ", e);
	    }
	    return null;
	  }

  /**
   * Retrieves the information about crawl behavior of a list of webs
   * corresponding to the passed in web urls
   *
   * @param weburls All web URLs whose crawl info is to be found
   */
  public WebCrawlInfo[] getWebCrawlInfoInBatchWithGoogleServices(String[] weburls) {
    WebCrawlInfo[] wsResult = null;
    if (null == weburls || weburls.length == 0) {
      return wsResult;
    }
    LOGGER.config("Fetching SharePoint indexing options for " + weburls.length
        + " web urls");
    try {
      wsResult = stub.getWebCrawlInfoInBatch(weburls);
    } catch (final AxisFault af) {
      if ((SPConstants.UNAUTHORIZED.indexOf(af.getFaultString()) != -1)
          && (sharepointClientContext.getDomain() != null)) {
        final String username = Util.switchUserNameFormat(stub.getUsername());
        LOGGER.log(Level.CONFIG, "Web Service call failed for username [ "
            + stub.getUsername() + " ]. Trying with " + username);
        stub.setUsername(username);
        try {
          wsResult = stub.getWebCrawlInfoInBatch(weburls);
        } catch (final Exception e) {
          LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.getWebCrawlInfoInBatch() failed with the following exception: ", e);
        }
      } else {
        LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.getWebCrawlInfoInBatch() failed with the following exception: ", af);
      }
    } catch (final Throwable e) {
      LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.getWebCrawlInfoInBatch() failed with the following exception: ", e);
    }
    return wsResult;
  }
  
  
  public WebCrawlInfo[] getWebCrawlInfoInBatchWithoutGoogleServices(String[] weburls) {
	    List<WebCrawlInfo> wsResult = new ArrayList<WebCrawlInfo>();
	    if (null == weburls || weburls.length == 0) {
	        return null;
	      }
	    String endpoint_siteData_tmp = null;
	    SiteDataSoap_BindingStub stub_siteData_tmp = null;
	    String strDomain = sharepointClientContext.getDomain();
	    String strUser = sharepointClientContext.getUsername();
	    String strPassword = sharepointClientContext.getPassword();
	    strUser = Util.getUserNameWithDomain(strUser, strDomain); 
	    try{
		for(String url:weburls){
			endpoint_siteData_tmp = Util.encodeURL(url)
					+ SPConstants.SITEDATAENDPOINT;
			final SiteDataLocator loc_siteData_tmp = new SiteDataLocator();
			loc_siteData_tmp.setSiteDataSoapEndpointAddress(endpoint_siteData_tmp);
			final SiteData gspSiteData_tmp = loc_siteData_tmp;
			try {
				stub_siteData_tmp = (SiteDataSoap_BindingStub) gspSiteData_tmp
						.getSiteDataSoap();
			} catch (final ServiceException e) {
				LOGGER.log(Level.WARNING, e.getMessage(), e);
			}
			stub_siteData_tmp.setUsername(strUser);
			stub_siteData_tmp.setPassword(strPassword);
			stub_siteData_tmp.setTimeout(sharepointClientContext
					.getWebServiceTimeOut());
			javax.xml.rpc.holders.StringHolder lastChangeID = new javax.xml.rpc.holders.StringHolder();
			String resultS = stub_siteData_tmp
					.getContent(
							com.google.enterprise.connector.sharepoint.generated.sitedata.ObjectType
									.fromString("Site"), "", "", "", true,
							true, lastChangeID);
			boolean nocrawl = getNoIndexFromContent(resultS);
			wsResult.add(new WebCrawlInfo(url,true,nocrawl,true,""));
		}     
	      return (WebCrawlInfo[])wsResult.toArray(new WebCrawlInfo[wsResult.size()]);
	    } catch (final AxisFault af) {
	      if ((SPConstants.UNAUTHORIZED.indexOf(af.getFaultString()) != -1)
	          && (sharepointClientContext.getDomain() != null)) {
	        strUser = Util.switchUserNameFormat(stub_siteData_tmp.getUsername());
	        LOGGER.log(Level.CONFIG, "Web Service call failed for username [ "
	            + stub_siteData_tmp.getUsername() + " ]. Trying with " + strUser);
	        try {
				for(String url:weburls){
					endpoint_siteData_tmp = Util.encodeURL(url)
							+ SPConstants.SITEDATAENDPOINT;
					final SiteDataLocator loc_siteData_tmp = new SiteDataLocator();
					loc_siteData_tmp.setSiteDataSoapEndpointAddress(endpoint_siteData_tmp);
					final SiteData gspSiteData_tmp = loc_siteData_tmp;
					try {
						stub_siteData_tmp = (SiteDataSoap_BindingStub) gspSiteData_tmp
								.getSiteDataSoap();
					} catch (final ServiceException e) {
						LOGGER.log(Level.WARNING, e.getMessage(), e);
					}
					stub_siteData_tmp.setUsername(strUser);
					stub_siteData_tmp.setPassword(strPassword);
					stub_siteData_tmp.setTimeout(sharepointClientContext
							.getWebServiceTimeOut());
					javax.xml.rpc.holders.StringHolder lastChangeID = new javax.xml.rpc.holders.StringHolder();
					String resultS = stub_siteData_tmp
							.getContent(
									com.google.enterprise.connector.sharepoint.generated.sitedata.ObjectType
											.fromString("Site"), "", "", "", true,
									true, lastChangeID);
					boolean nocrawl = getNoIndexFromContent(resultS);
					wsResult.add(new WebCrawlInfo(url,true,nocrawl,true,""));
				}
	          } catch (final Exception e) {
	            LOGGER.log(Level.WARNING, "Call to siteData.getWebCrawlInfoInBatch() failed with the following exception: ", e);
	          }	        
	      } else {
	        LOGGER.log(Level.WARNING, "Call to siteData.getWebCrawlInfoInBatch() failed with the following exception: ", af);
	      }
	    } catch (final Throwable e) {
	      LOGGER.log(Level.WARNING, "Call to siteData.getWebCrawlInfoInBatch() failed with the following exception: ", e);
	    }
	    return (WebCrawlInfo[])wsResult.toArray(new WebCrawlInfo[wsResult.size()]);
	  }
  /**
   * Retrieves and update the information about crawl behavior of a set of webs
   *
   * @param webs
   */
  public void updateWebCrawlInfoInBatch(Set<WebState> webs) {
    if (null == webs || webs.size() == 0) {
      return;
    }
    final Map<String, List<WebState>> webappToWeburlMap = arrangeWebUrlPerWebApp(webs);
    LOGGER.log(Level.CONFIG, webappToWeburlMap.size()
        + " WS call(s) will be made to get WebCrawlInfo of " + webs.size()
        + " sites");

    for (Entry<String, List<WebState>> entry : webappToWeburlMap.entrySet()) {
      GSSiteDiscoveryWS sitews = null;
      try {
        sitews = new GSSiteDiscoveryWS(sharepointClientContext, entry.getKey());
      } catch (Exception e) {
        LOGGER.log(Level.WARNING, "Failed to initialize stub for "
            + entry.getKey(), e);
        continue;
      }
      Map<String, WebState> webUrlMap = new HashMap<String, WebState>();
      String[] weburls = new String[webs.size()];
      int i = 0;
      for (WebState web : entry.getValue()) {
        weburls[i++] = web.getWebUrl();
        webUrlMap.put(web.getWebUrl(), web);
      }
      WebCrawlInfo[] webCrawlInfos;
      if (sharepointClientContext.isEnabledGoogleServices())
    	  webCrawlInfos = sitews.getWebCrawlInfoInBatchWithGoogleServices(weburls);
      else
    	  webCrawlInfos = sitews.getWebCrawlInfoInBatchWithoutGoogleServices(weburls);
      if (null == webCrawlInfos) {
        return;
      }
      for (WebCrawlInfo webCrawlInfo : webCrawlInfos) {
        if (webCrawlInfo.isStatus()) {
          WebState webState = webUrlMap.get(webCrawlInfo.getWebKey());
          webState.setWebCrawlInfo(webCrawlInfo);
        } else {
          LOGGER.log(Level.WARNING, "WS encountered problem while fetching the crawl info of one of the web. WS ERROR -> "
              + webCrawlInfo.getError());
        }
      }
    }
  }

  /**
   * Retrieves the information about crawl behavior of a the lists and set it
   * into the passed in {@link ListState}
   *
   * @param listCollection ListStates to be be updated
   */
  public void updateListCrawlInfo(Collection<ListState> listCollection) {
    if (null == listCollection || !sharepointClientContext.isEnabledGoogleServices()) {
      return;
    }
    Map<String, ListState> listCrawlInfoMap = new HashMap<String, ListState>();
    String[] listGuids = new String[listCollection.size()];
    int i = 0;
    for (ListState listState : listCollection) {
      listGuids[i++] = listState.getPrimaryKey();
      listCrawlInfoMap.put(listState.getPrimaryKey(), listState);
    }
    ListCrawlInfo[] listCrawlInfo = null;
    try {
      listCrawlInfo = stub.getListCrawlInfo(listGuids);
    } catch (final AxisFault af) {
      if ((SPConstants.UNAUTHORIZED.indexOf(af.getFaultString()) != -1)
          && (sharepointClientContext.getDomain() != null)) {
        final String username = Util.switchUserNameFormat(stub.getUsername());
        LOGGER.log(Level.CONFIG, "Web Service call failed for username [ "
            + stub.getUsername() + " ]. Trying with " + username);
        stub.setUsername(username);
        try {
          listCrawlInfo = stub.getListCrawlInfo(listGuids);
        } catch (final Exception e) {
          LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.GetListCrawlInfo() failed with the following exception: ", e);
        }
      } else {
        LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.GetListCrawlInfo() failed with the following exception: ", af);
      }
    } catch (final Throwable e) {
      LOGGER.log(Level.WARNING, "Call to GSSiteDiscovery.GetListCrawlInfo() failed with the following exception: ", e);
    }

    if (null == listCrawlInfo) {
      return;
    }

    for (ListCrawlInfo info : listCrawlInfo) {
      ListState listState = listCrawlInfoMap.get(info.getListGuid());
      if (null == listState) {
        LOGGER.log(Level.SEVERE, "One of the List GUID [ " + info.getListGuid()
            + " ] can not be found in the parentWebState. ");
        continue;
      }
      if (!info.isStatus()) {
        LOGGER.log(Level.WARNING, "GSSiteDiscovery has encountered following problem while getting the crawl info for list URL [ "
            + listState.getListURL()
            + " ]. List GUID [ "
            + listState.getPrimaryKey()
            + " ]. Using endpoint [ "
            + endpoint
            + " ]. WS error -> " + info.getError());
        continue;
      }
      listState.setNoCrawl(info.isNoCrawl());
    }
  }

  /**
   * Arranges URLs of all the webs according to their web application.
   *
   * @param webs
   * @return A map where the web application is mapped to the hosted webstates
   */
  private Map<String, List<WebState>> arrangeWebUrlPerWebApp(
      final Set<WebState> webs) {
    final Map<String, List<WebState>> webappToWeburlMap = new HashMap<String, List<WebState>>();
    for (WebState web : webs) {
      // We need to arrange all the URLs according to their web
      // application because the WS call for batch processing of URLs can
      // be made per web application only. If a url do not belongs to the
      // web app that was used while setting the endpoint, ws call will
      // fail
      final String webApp = Util.getWebApp(web.getWebUrl());
      List<WebState> lstWebs = webappToWeburlMap.get(webApp);
      if (null == lstWebs) {
        lstWebs = new ArrayList<WebState>();
        webappToWeburlMap.put(webApp, lstWebs);
      }
      lstWebs.add(web);
    }
    return webappToWeburlMap;
  }
}

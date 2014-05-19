// Copyright 2011 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package com.google.enterprise.connector.sharepoint.wsclient.soap;

import com.google.enterprise.connector.sharepoint.client.SharepointClientContext;
import com.google.enterprise.connector.sharepoint.client.Util;
import com.google.enterprise.connector.sharepoint.spiimpl.SharepointException;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.HeadMethod;
import org.apache.commons.httpclient.params.HttpClientParams;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;


public class SPClientFactory {
  private static final Logger LOGGER = Logger.getLogger(SPClientFactory.class.getName());
  private static final int HTTP_CLIENT_TIMEOUT_SECONDS = 300;
  
  private static class Resource {
    private final HttpClient httpClient;
    private final Set<String> webAppsVisited;
    
    public Resource (HttpClient inHttpClient) {
      httpClient = inHttpClient;
      webAppsVisited = new TreeSet<String>();
    }
  }
  
  private final BlockingQueue<Resource> resources =
      new ArrayBlockingQueue<Resource>(4);


  public int checkConnectivity(HttpMethodBase method,
      Credentials credentials) throws IOException {
    Resource resource = reserveResource(credentials);
    String currentWebApp = Util.getWebApp(method.getURI().getURI());
    try {
      int responseCode = resource.httpClient.executeMethod(method);
      if (responseCode == 200) {
        // Add web app entry when response code is 200
        resource.webAppsVisited.add(currentWebApp);
      }
      if (responseCode != 200 && responseCode != 404 && responseCode != 400) {
        LOGGER.log(Level.WARNING,
            "Http Response Code = "+ responseCode + " for Url [ "
                + method.getURI() + " ].");

        if (responseCode == 401 &&
            resource.webAppsVisited.contains(currentWebApp)) {
          LOGGER.log(Level.WARNING, "Not reinitializing HTTP Client after "
              + "[ 401 ] response as connection to Web Application [ "
              + currentWebApp
              + " ] was successful earlier with existing HTTP Client Object.");
          return responseCode;
        }

        LOGGER.log(Level.WARNING, "Reinitializing HTTP Client as [ "
            + responseCode + " ] response received.");
        resource = new Resource(createHttpClient(credentials));        
        responseCode = resource.httpClient.executeMethod(method);
        if (responseCode == 200) {
          // Add web app entry when response code is 200
          resource.webAppsVisited.add(currentWebApp);
        }
      }
      returnResource(resource);
      return responseCode;      
    } catch(Exception ex) {    
      LOGGER.log(Level.WARNING,
          "Error Connecting Server for Url [ "
              + method.getURI() + " ]. Reinitializing HttpClient.", ex);
      resource = new Resource(createHttpClient(credentials));      
      int responseCode = resource.httpClient.executeMethod(method);
      if (responseCode == 200) {
        // Add web app entry when response code is 200
        resource.webAppsVisited.add(currentWebApp);       
      }
      returnResource(resource);
      return responseCode;
    }
  }
  
  private HttpClient createHttpClient(Credentials credentials) {
    HttpClient httpClientToUse = new HttpClient();

    HttpClientParams params = httpClientToUse.getParams();
    // Fix for the Issue[5408782] SharePoint connector fails to traverse a site,
    // circular redirect exception is observed.
    params.setBooleanParameter(HttpClientParams.ALLOW_CIRCULAR_REDIRECTS, true);
    // If ALLOW_CIRCULAR_REDIRECTS is set to true, HttpClient throws an
    // exception if a series of redirects includes the same resources more than
    // once. MAX_REDIRECTS allows you to specify a maximum number of redirects
    // to follow.
    params.setIntParameter(HttpClientParams.MAX_REDIRECTS, 10);
    
    params.setLongParameter(HttpClientParams.CONNECTION_MANAGER_TIMEOUT,
        HTTP_CLIENT_TIMEOUT_SECONDS * 1000);
    params.setIntParameter(HttpClientParams.SO_TIMEOUT,
        HTTP_CLIENT_TIMEOUT_SECONDS * 1000);
    httpClientToUse.getState().setCredentials(AuthScope.ANY, credentials);
    return httpClientToUse;
  }
  
  private Resource reserveResource(Credentials credentials) throws IOException {
    Resource resource = null;
    try {
      LOGGER.log(Level.FINEST,
          "Number of resources in resource pool = " + resources.size());
      resource = resources.poll(0, TimeUnit.SECONDS);      
    } catch (InterruptedException e) {      
      throw new IOException("Unable to reserve resource", e);      
    }
    // Create new resource.
    if (resource == null) {
      resource = new Resource(createHttpClient(credentials));
    } else {
      // Clear cookies if reusing http client from
      // resource pool.
      resource.httpClient.getState().clearCookies();
    }
    return resource;
  }
  
  private void returnResource(Resource resource) {
    resources.offer(resource);
  }
  
  public String getResponseHeader(HttpMethodBase method, String headerName) {
    String headerValue = null;
    final Header header = method.getResponseHeader(headerName);
    if (null != header) {
      headerValue = header.getValue();
    }
    return headerValue;
  }

}


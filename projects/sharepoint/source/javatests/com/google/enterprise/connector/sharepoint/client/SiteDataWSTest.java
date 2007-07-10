// Copyright 2007 Google Inc.  All Rights Reserved.
package com.google.enterprise.connector.sharepoint.client;

import com.google.enterprise.connector.spi.RepositoryException;

import junit.framework.TestCase;

import java.util.List;

/**
 *
 */
public class SiteDataWSTest extends TestCase {  
  final String sharepointUrl = "http://entpoint05.corp.google.com/unittest";
  final String sharepointUrlWithSpaces = 
      "http://entpoint05.corp.google.com/site with spaces";
  final String domain = "ent-qa-d3";
  final String host = "entpoint05.corp.google.com";
  final int port = 80;
  final String username = "testing";
  final String password = "g00gl3";
  private SiteDataWS siteDataWS;
  private ListsWS listsWS;
  
  /* (non-Javadoc)
   * @see junit.framework.TestCase#setUp()
   */
  protected void setUp() throws Exception {
    SharepointClientContext sharepointClientContext = new 
      SharepointClientContext(sharepointUrl, domain, username, password, null); 
    siteDataWS = new SiteDataWS(sharepointClientContext);   
    listsWS = new ListsWS(sharepointClientContext);
    super.setUp();
  }

  /**
   * Test method for {@link 
   * com.google.enterprise.connector.sharepoint.client.SiteDataWS#getSites()}.
   */
  public void testGetAllChildrenSites() {
    int i = 0;
    try {
      List sites = siteDataWS.getAllChildrenSites();
      System.out.println("Sites found - ");
      for (; i < sites.size(); i++) {
        SPDocument doc = (SPDocument) sites.get(i);
        System.out.println(doc.getUrl());
      }
      assertEquals(i, 5);
    } catch (SharepointException e) {      
      e.printStackTrace();
      fail();
    }   
  }

  public void testSiteWithSpaces() {
    
    int numDocLib = 0;    
    try {
      SharepointClientContext sharepointClientContextSpaces = new 
      SharepointClientContext(sharepointUrlWithSpaces, 
          domain, username, password, null); 
      SiteDataWS siteDataWSSpaces = 
          new SiteDataWS(sharepointClientContextSpaces);   
      List listCollection = siteDataWSSpaces.getDocumentLibraries();
      System.out.println("SPDocument Libraries found - ");
      for (int i = 0; i < listCollection.size(); i++) {
        BaseList baseList = (BaseList) listCollection.get(i);
        System.out.println(baseList.getTitle());        
        numDocLib++;        
      }
      assertEquals(1, numDocLib);
    } catch (SharepointException e) {
      e.printStackTrace();
      fail();
    } catch (RepositoryException e1) {
      e1.printStackTrace();
      fail();
    }    
  }
  /**
   * Test method for {@link 
   * com.google.enterprise.connector.sharepoint.client.SiteDataWS
   * #getDocumentLibraries()}.
   */
  public void testGetDocumentLibraries() {
    int numDocLib = 0;
    try {
      List listCollection = siteDataWS.getDocumentLibraries();
      System.out.println("SPDocument Libraries found - ");
      for (int i = 0; i < listCollection.size(); i++) {
        BaseList baseList = (BaseList) listCollection.get(i);
        System.out.println(baseList.getTitle());        
        numDocLib++;        
      }
      assertEquals(2, numDocLib);
    } catch (SharepointException e) {
      e.printStackTrace();
      fail();
    }
  }
  
  public void testGetGenericLists() {
    int numGenList = 0;
    try {
      List listCollection = siteDataWS.getGenericLists();
      System.out.println("Generic Lists found - ");
      for (int i = 0; i < listCollection.size(); i++) {
        BaseList baseList = (BaseList) listCollection.get(i);
        System.out.println(baseList.getTitle());        
        numGenList++;        
      }
      assertEquals(9, numGenList);
    } catch (SharepointException e) {      
      e.printStackTrace();
      fail();
    }
  }
  
  public void testIssues() {
    int numIssues = 0;
    try {
      List listCollection = siteDataWS.getIssues();
      System.out.println("Issues found - ");
      for (int i = 0; i < listCollection.size(); i++) {
        BaseList baseList = (BaseList) listCollection.get(i);
        System.out.println(baseList.getTitle());        
        numIssues++;        
      }
      assertEquals(1, numIssues);
    } catch (SharepointException e) {      
      e.printStackTrace();
      fail();
    }
  }
}

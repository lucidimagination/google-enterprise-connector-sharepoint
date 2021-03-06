<%@ WebService Language="C#" Class="SiteDiscovery" %>
using System;
using System.Collections;
using System.Web;
using System.Web.Services;
using System.Web.Services.Protocols;
using Microsoft.SharePoint;
using Microsoft.SharePoint.Administration;

[WebService(Namespace = "gssitediscovery.generated.sharepoint.connector.enterprise.google.com")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
public class SiteDiscovery : System.Web.Services.WebService
{
    public SiteDiscovery  () {

        //Uncomment the following line if using designed components 
        //InitializeComponent(); 
    }

    /// <summary>
    /// Check connectivity of the GSP Site discovery service.
    /// </summary>
    /// <returns></returns>
    [WebMethod]
    public string CheckConnectivity() {
        try
        {
            SPWebApplicationCollection wc = SPWebService.AdministrationService.WebApplications;
			SPWebApplicationCollection wc2 = SPWebService.ContentService.WebApplications;
        }
        catch (Exception e)
        {
            return e.StackTrace;
        }

        return "success";
    }

    /// <summary>
    /// Get the top level URL of all site collections form all web applications for a given sharepoint installation.
    /// </summary>
    /// <returns></returns>
    [WebMethod]
    public ArrayList GetAllSiteCollectionFromAllWebApps()
    {
        ArrayList webSiteList = new ArrayList();

        //get the site collection for the central administration
        foreach (SPWebApplication wa in SPWebService.AdministrationService.WebApplications)
        {
            foreach (SPSite sc in wa.Sites)
            {
                try
                {
                    //add the site collection top level url in\to our arraylist
                    webSiteList.Add(sc.Url);
                }                
                finally
                {
                    sc.Dispose();
                }
            }
        }

        foreach (SPWebApplication wa in SPWebService.ContentService.WebApplications)
        {
            //Console.WriteLine("web Application: " + wa.Name);
            foreach (SPSite sc in wa.Sites)
            {
                try
                {
                    webSiteList.Add(sc.Url);
                }
                finally
                {
                    sc.Dispose();
                }
            }
        }
        return webSiteList;//return the list
    }
    
}


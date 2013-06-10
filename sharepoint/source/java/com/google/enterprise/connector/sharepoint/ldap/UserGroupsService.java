//Copyright 2011 Google Inc.

//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

package com.google.enterprise.connector.sharepoint.ldap;

import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.google.enterprise.connector.sharepoint.client.SPConstants;
import com.google.enterprise.connector.sharepoint.client.SharepointClientContext;
import com.google.enterprise.connector.sharepoint.client.Util;
import com.google.enterprise.connector.sharepoint.dao.UserDataStoreDAO;
import com.google.enterprise.connector.sharepoint.dao.UserGroupMembership;
import com.google.enterprise.connector.sharepoint.ldap.LdapConstants.AuthType;
import com.google.enterprise.connector.sharepoint.ldap.LdapConstants.LdapConnectionError;
import com.google.enterprise.connector.sharepoint.ldap.LdapConstants.Method;
import com.google.enterprise.connector.sharepoint.ldap.LdapConstants.ReadAdGroupsType;
import com.google.enterprise.connector.sharepoint.ldap.LdapConstants.ServerType;
import com.google.enterprise.connector.sharepoint.spiimpl.SharepointAuthenticationManager;
import com.google.enterprise.connector.sharepoint.spiimpl.SharepointException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.AuthenticationException;
import javax.naming.AuthenticationNotSupportedException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

/**
 * An implementation of {@link LdapService} and encapsulates all interaction
 * with JNDI to get {@link LdapContext} and {@link LdapConnection} with
 * {@link LdapConnectionSettings} provided by
 * {@link SharepointAuthenticationManager} and also it talks to
 * {@link UserDataStoreDAO} to get all SP groups. This implementation is
 * specific to Active Directory service at the moment.
 * 
 * @author nageswara_sura
 */
public class UserGroupsService implements LdapService {

	private static final Logger LOGGER = Logger.getLogger(UserGroupsService.class.getName());

	private LdapConnectionSettings ldapConnectionSettings;
	private LdapContext context;
	private UserGroupsCache<Object, ConcurrentHashMap<String, Set<String>>> lugCacheStore = null;
	private LdapConnection ldapConnection;
	private SharepointClientContext sharepointClientContext;

	public UserGroupsService() {

	}

	/**
	 * Initializes LDAP context object for a given {@link LdapConnectionSettings}
	 * and also Constructs {@code LdapUserGroupsCache} cache with a refresh
	 * interval and custom capacity.
	 * 
	 * @param ldapConnectionSettings
	 */
	public UserGroupsService(LdapConnectionSettings ldapConnectionSettings,
			int cacheSize, long refreshInterval, boolean enableLUGCache) {
		this.ldapConnectionSettings = ldapConnectionSettings;
		ldapConnection = new LdapConnection(ldapConnectionSettings);
		context = getLdapContext();
		if (enableLUGCache) {
			this.lugCacheStore = new UserGroupsCache<Object, ConcurrentHashMap<String, Set<String>>>(
					refreshInterval, cacheSize);
			LOGGER.log(Level.CONFIG, "Configured user groups cache store with refresh interval [ "
					+ refreshInterval + " ] and with capacity [ " + cacheSize + " ]");
		} else {
			LOGGER.log(Level.CONFIG, "No cache has been configured to keep user groups memberships.");
		}
	}

	public UserGroupsService(LdapConnectionSettings ldapConnectionSettings,
			SharepointClientContext inSharepointClientContext) {
		if (!Strings.isNullOrEmpty(ldapConnectionSettings.getHostname())
				|| !Strings.isNullOrEmpty(ldapConnectionSettings.getBaseDN())) {
			this.ldapConnectionSettings = ldapConnectionSettings;
			ldapConnection = new LdapConnection(ldapConnectionSettings);
			context = getLdapContext();
		} else {
			LOGGER.warning("Not attempting to create LDAP context, because LDAP host name or base DN is empty or null.");
		}

		this.sharepointClientContext = inSharepointClientContext;
		if (sharepointClientContext.isUseCacheToStoreLdapUserGroupsMembership()) {
			this.lugCacheStore = new UserGroupsCache<Object, ConcurrentHashMap<String, Set<String>>>(
					sharepointClientContext.getCacheRefreshInterval(),
					sharepointClientContext.getInitialCacheSize());
		} else {
			LOGGER.log(Level.INFO, "No cache has been configured to keep user groups memberships.");
		}
	}

	public UserGroupsService(SharepointClientContext inSharepointClientContext) {
		this(inSharepointClientContext.getLdapConnectionSettings(),
				inSharepointClientContext);
	}

	/**
	 * A setter method used to set {@link LdapConnectionSettings} and creates a
	 * {@link LdapConnection} object.
	 * 
	 * @param ldapConnectionSettings to initialize and create
	 *          {@link LdapConnection}
	 */
	public void setLdapConnectionSettings(
			LdapConnectionSettings ldapConnectionSettings) {
		this.ldapConnectionSettings = ldapConnectionSettings;
		ldapConnection = new LdapConnection(ldapConnectionSettings);

	}

	public UserGroupsCache<Object, ConcurrentHashMap<String, Set<String>>> getLugCacheStore() {
		return lugCacheStore;
	}

	public LdapConnection getLdapConnection() {
		return ldapConnection;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.google.enterprise.connector.sharepoint.ldap.LdapService#getLdapContext
	 * ()
	 */
	public LdapContext getLdapContext() {
		return ldapConnection.getLdapContext();
	}

	public Map<LdapConnectionError, String> getErrors() {
		if (ldapConnection != null) {
			return ldapConnection.getErrors();
		}
		throw new IllegalStateException(
				"Must successfully set connection config before getting error state");
	}

	public static class LdapConnection {

		private final LdapConnectionSettings settings;
		private LdapContext ldapContext = null;
		private final Map<LdapConnectionError, String> errors;

		public LdapConnection(LdapConnectionSettings ldapConnectionSettings) {
			LOGGER.info(ldapConnectionSettings.toString());
			this.settings = ldapConnectionSettings;
			Hashtable<String, String> env = configureLdapEnvironment();
      this.errors = Maps.newHashMap();
			this.ldapContext = createContext(env);
		}

		/**
		 * @return Map of errors with {@link LdapConnectionError} as a key and
		 *         detailed error message as a value.
		 */
		public Map<LdapConnectionError, String> getErrors() {
			return errors;
		}

		/**
		 * Returns initial {@link LdapContext}
		 */
		public LdapContext getLdapContext() {
			return ldapContext;
		}

		private LdapContext createContext() {
			return createContext(configureLdapEnvironment());
		}

		/**
		 * Returns {@link LdapContext} object.
		 * 
		 * @param env hold LDAP
		 * @return {@link LdapContext}
		 */
		private LdapContext createContext(Hashtable<String, String> env) {
			LdapContext ctx = null;
			try {
				ctx = new InitialLdapContext(env, null);
			} catch (CommunicationException e) {
				errors.put(LdapConnectionError.CommunicationException, e.getCause().toString());
				LOGGER.log(Level.WARNING, "Could not obtain an initial context to query LDAP (Active Directory) due to a communication failure.", e);
			} catch (AuthenticationNotSupportedException e) {
				errors.put(LdapConnectionError.AuthenticationNotSupportedException, e.getCause().toString());
				LOGGER.log(Level.WARNING, "Could not obtain an initial context to query LDAP (Active Directory) due to authentication not supported exception.", e);
			} catch (AuthenticationException ae) {
				errors.put(LdapConnectionError.AuthenticationFailedException, ae.getCause().toString());
				LOGGER.log(Level.WARNING, "Could not obtain an initial context to query LDAP (Active Directory) due to authentication exception.", ae);
			} catch (NamingException e) {
				errors.put(LdapConnectionError.NamingException, e.getCause().toString());
				LOGGER.log(Level.WARNING, "Could not obtain an initial context to query LDAP (Active Directory) due to a naming exception.", e);
			}
			if (ctx == null) {
				return null;
			}
			LOGGER.info("Sucessfully created an Initial LDAP context");
			return ctx;
		}

		/**
		 * Makes an LDAP or LDAPS URL. The default port for LDAPS URLs is 636 where
		 * as for LDAP URLs it is 389.
		 * 
		 * @return a LDAP or LDAPS URL bases on the {@link Method}
		 */
		private String makeLdapUrl() {
			String url;
			Method connectMethod = settings.getConnectMethod();
			if (connectMethod == Method.SSL) {
				url = "ldaps://"; // For SSL
			} else {
				url = "ldap://"; // for NON-SSL
			}

			// Construct the full URL
			url = url + settings.getHostname();
			if (settings.getPort() > 0) {
				url = url + ":" + settings.getPort();
			}

			LOGGER.info("Complete LDAP URL : " + url);
			return url;
		}

		/*
		 * Initialize the {@link java.util.HashSet} used to create an initial LDAP Context.
		 * Note that we specifically require a {@link java.util.HashSet} rather than a
		 * HashMap as the parameter type in the InitialLDAPContext constructor
		 * 
		 * @return initialized {@link java.util.HashSet} suitable for constructing an
		 *         InitiaLdaplContext
		 */
		private Hashtable<String, String> configureLdapEnvironment() {
			Hashtable<String, String> env = new Hashtable<String, String>();
			// Use the built-in LDAP support.
			env.put(Context.INITIAL_CONTEXT_FACTORY, LdapConstants.COM_SUN_JNDI_LDAP_LDAP_CTX_FACTORY);

			// Set our authentication settings.
			AuthType authType = settings.getAuthType();
			if (authType == AuthType.SIMPLE) {
				env.put(Context.SECURITY_AUTHENTICATION, authType.toString().toLowerCase());
				env.put(Context.SECURITY_PRINCIPAL, settings.getUsername()
						+ SPConstants.AT + settings.domainName);
				env.put(Context.SECURITY_CREDENTIALS, settings.getPassword());
				LOGGER.info("Using simple authentication.");
			} else {
				if (authType != AuthType.ANONYMOUS) {
					LOGGER.warning("Unknown authType - falling back to anonymous.");
				} else {
					LOGGER.info("Using anonymous authentication.");
				}
				env.put(Context.SECURITY_AUTHENTICATION, "none"); //$NON-NLS-1$
			}
			env.put(Context.REFERRAL, "follow");
			env.put(Context.PROVIDER_URL, makeLdapUrl());
			return env;
		}
	}

	public static class LdapConnectionSettings {
		private final String hostName;
		private final int port;
		private String domainName;
		private final AuthType authType;
		private final String userName;
		private final String password;
		private final Method connectMethod;
		private final String baseDN;
		private final ServerType serverType;
		private final ReadAdGroupsType readAdGroupsType;

		public LdapConnectionSettings(Method connectMethod, String hostname,
				int port, String baseDN, AuthType authType, String userName,
				String password, String domainName, ReadAdGroupsType readAdGroupsType) {
			this.authType = authType;
			this.baseDN = baseDN;
			this.connectMethod = connectMethod;
			this.hostName = hostname;
			this.password = password;
			this.port = port;
			this.serverType = ServerType.getDefault();
			this.userName = userName;
			this.domainName = domainName;
			this.readAdGroupsType = readAdGroupsType;
		}

		public LdapConnectionSettings(Method standard, String hostName, int port,
				String baseDN, String domainName, ReadAdGroupsType readAdGroupsType) {
			this.authType = AuthType.ANONYMOUS;
			this.baseDN = baseDN;
			this.connectMethod = standard;
			this.hostName = hostName;
			this.password = null;
			this.port = port;
			this.serverType = ServerType.getDefault();
			this.userName = null;
			this.domainName = domainName;
			this.readAdGroupsType = readAdGroupsType;
		}

		@Override
		public String toString() {
			String displayPassword;
			if (password == null) {
				displayPassword = "null";
			} else if (password.length() < 1) {
				displayPassword = "<empty>";
			} else {
				displayPassword = "####";
			}
			return "LdapConnectionSettings [authType=" + authType + ", baseDN="
					+ baseDN + ", connectMethod=" + connectMethod + ", hostname="
					+ hostName + ", password=" + displayPassword + ", port=" + port
					+ ", serverType=" + serverType + ", userName=" + userName
					+ ", domainName =" + domainName + ", readAdGroupsType=" + readAdGroupsType + " ]";
		}

		public AuthType getAuthType() {
			return authType;
		}
		
		public ReadAdGroupsType getReadAdGroupsType() {
      return readAdGroupsType;
    }

    public String getBaseDN() {
			return baseDN;
		}

		public Method getConnectMethod() {
			return connectMethod;
		}

		public String getHostname() {
			return hostName;
		}

		public String getPassword() {
			return password;
		}

		public int getPort() {
			return port;
		}

		public ServerType getServerType() {
			return serverType;
		}

		public String getUsername() {
			return userName;
		}

		public String getDomainName() {
			return domainName;
		}
	}

	/**
	 * Takes user SID as binary string, group RID as string and converts them to escaped hexa
	 * representation of LDAP search filter
	 *
	 * @param sid user binary SID
	 * @param primaryGroupId primary group RID (guaranteed to be within user's domain)
	 * @return string containing LDAP search filter for user's primary group
	 */
	String createSearchFilterForPrimaryGroup(byte[] sid, String primaryGroupId) {
		long primaryGroup = Long.parseLong(primaryGroupId);
		// replace the last four bytes of user's SID with group RID
		sid[sid.length - 1] = (byte)((primaryGroup >> 24) & 0xFF);
		sid[sid.length - 2] = (byte)((primaryGroup >> 16) & 0xFF);
		sid[sid.length - 3] = (byte)((primaryGroup >> 8) & 0xFF);
		sid[sid.length - 4] = (byte)(primaryGroup & 0xFF);
		// format the SID as escaped hexa (i.e. \01\05\ff...)
		StringBuilder primaryGroupSid = new StringBuilder();
		primaryGroupSid.append(LdapConstants.PREFIX_FOR_PRIMARY_GROUP_FILTER);
		for (int i = 0; i < sid.length; ++i) {
			int unsignedByte = sid[i] & 0xFF;
			// add zero padding for single digits
			if (unsignedByte < 16)
				primaryGroupSid.append("\\0");
			else
				primaryGroupSid.append("\\");
			primaryGroupSid.append(Integer.toHexString(unsignedByte));
		}
		primaryGroupSid.append(")");
		return primaryGroupSid.toString();
	}
	
  /**
   * See http://blogs.msdn.com/b/alextch/archive/2007/06/18/sample-java-application-that-retrieves-group-membership-of-an-active-directory-user-account.aspx
   * @param SID
   * @return
   */
	public static final String binarySidToStringSid(byte[] SID) {
    String strSID = "";
    // convert the SID into string format
    long version;
    long authority;
    long count;
    long rid;
    strSID = "S";
    version = SID[0];
    strSID = strSID + "-" + Long.toString(version);
    authority = SID[4];
    for (int i = 0; i < 4; i++) {
      authority <<= 8;
      authority += SID[4 + i] & 0xFF;
    }
    strSID = strSID + "-" + Long.toString(authority);
    count = SID[2];
    count <<= 8;
    count += SID[1] & 0xFF;
    for (int j = 0; j < count; j++) {
      rid = SID[11 + (j * 4)] & 0xFF;
      for (int k = 1; k < 4; k++) {
        rid <<= 8;
        rid += SID[11 - k + (j * 4)] & 0xFF;
      }
      strSID = strSID + "-" + Long.toString(rid);
    }
    return strSID;
  }
	
	/**
	 * Returns user's primary group
	 * 
	 * @param userSid SID of the user in Active Directory
	 * @param primaryGroupId domain local ID of the primary group
	 * @param returnSamAccountName
	 * @return string containing the primary group's name (dn or samAccountName)
	 */
	String getPrimaryGroupForTheSearchUser(byte[] userSid, String primaryGroupId, boolean returnSamAccountName) {
	  long startTime = System.currentTimeMillis();
		if (userSid == null || primaryGroupId == null) {
			return null;
		}
		String primaryGroupDN = null;
		String samAccountName = null;
		SearchControls searchCtls = makeSearchCtls(new String[]{LdapConstants.ATTRIBUTE_SAMACCOUNTNAME});
		// Create the search filter
		String searchFilter = createSearchFilterForPrimaryGroup(userSid, primaryGroupId);
		// Specify the Base DN for the search
		String searchBase = ldapConnectionSettings.getBaseDN();
		NamingEnumeration<SearchResult> ldapResults = null;
		try {
			ldapResults = this.context.search(searchBase, searchFilter, searchCtls);
			if (ldapResults != null && ldapResults.hasMoreElements()) {
			  SearchResult sr = ldapResults.next();
			  primaryGroupDN = sr.getNameInNamespace();
			  samAccountName = (String) sr.getAttributes().get(LdapConstants.ATTRIBUTE_SAMACCOUNTNAME).get();
			}
		} catch (NamingException ne) {
			LOGGER.log(Level.WARNING, "Failed to retrieve primary group with SID: ["
					+ searchFilter + "]", ne);
		} finally {
			try {
				if (null != ldapResults) {
					ldapResults.close();
				}
			} catch (NamingException e) {
				LOGGER.log(Level.WARNING, "Exception during clean up of ldap results.", e);
			}
		}
		String result = primaryGroupDN;
    if (returnSamAccountName)
      result = samAccountName;

    long endTime = System.currentTimeMillis();
		LOGGER.log(Level.INFO, "AD query: base_dn=''{0}'', filter=''{1}'', attrs=''{2}'', time=''{3}''",
        new String[] { searchBase, searchFilter, Arrays.toString(searchCtls.getReturningAttributes()), (endTime - startTime) + "ms"  });
		LOGGER.log(Level.INFO, "AD primary group id resolved to ''{0}''", new String[] {result});
		
		return result;
	}
	
	/**
	 * Search all (direct and nested) AD groups using IN_CHAIN query
	 * @param dn
	 * @return list of groups (samAccountName attributes, not dn-s)
	 */
	Set<String> getLdapGroupsUsingInChainQuery(String dn) {
    long startTime = System.currentTimeMillis();
    // Create the search controls.
    SearchControls searchCtls = makeSearchCtls(new String[]{
      LdapConstants.ATTRIBUTE_SAMACCOUNTNAME
    });
    // Create the search filter.
    String searchFilter = createSearchFilterForInChainQuery(dn);
    // Specify the Base DN for the search.
    String searchBase = ldapConnectionSettings.getBaseDN();
    
    Set<String> result = new HashSet<String>();
    NamingEnumeration<SearchResult> ldapResults = null;
    try {
      ldapResults = this.context.search(searchBase, searchFilter, searchCtls);
      // Loop through the search results
      while (ldapResults.hasMoreElements()) {
        SearchResult sr = ldapResults.next();
        Attributes attrs = sr.getAttributes();
        if (attrs != null) {
          String samAccountName = (String) attrs.get(LdapConstants.ATTRIBUTE_SAMACCOUNTNAME).get();
          if (samAccountName != null)
            result.add(samAccountName);
        }
      }
    } catch (NamingException ne) {
      LOGGER.log(Level.WARNING, "Failed to retrieve all groups for the user name using IN_CHAIN rule: ["
          + dn + "]", ne);
    } finally {
      if (null != ldapResults) {
        try {
          ldapResults.close();
        } catch (NamingException e) {
          LOGGER.log(Level.WARNING, "Exception during clean up of ldap results", e);
        }
      }
    }
    
    long endTime = System.currentTimeMillis();
    LOGGER.log(Level.INFO, "AD query: base_dn=''{0}'', filter=''{1}'', attrs=''{2}'', time=''{3}''",
        new String[] { searchBase, searchFilter, Arrays.toString(searchCtls.getReturningAttributes()), (endTime - startTime) + "ms"  });
    LOGGER.log(Level.INFO, "Found ''{0}'' groups for user ''{1}'' using IN_CHAIN query:\n''{2}''", new Object[] {result.size(), dn, result});
    
    return result;
	}
	
	/**
	 * Get all (direct and nested) AD groups using tokenGroups attribute
	 * I.e. 
	 *  - parse groups objectSid ids out of tokenGroups attribute
	 *  - builds LDAP filter that lookups samAccountNames by objectSids 
	 * @param dn
	 * @return groups samAccountNames
	 */
	Set<String> getLdapGroupsUsingTokenGroups(String dn) {
    long startTime = System.currentTimeMillis();
    SearchControls searchCtls = new SearchControls();
    searchCtls.setSearchScope(SearchControls.OBJECT_SCOPE);
    searchCtls.setReturningAttributes(new String[] {LdapConstants.ATTRIBUTE_TOKEN_GROUPS});
    
    NamingEnumeration<SearchResult> ldapResults = null;
    
    Set<String> sids = new HashSet<String>(); 
    try {
      ldapResults = this.context.search(dn, LdapConstants.USER_SEARCH_FILTER, searchCtls);
      while (ldapResults.hasMoreElements()) {
        SearchResult sr = ldapResults.next();
        Attributes attrs = sr.getAttributes();
        if (attrs != null) {
          for (NamingEnumeration<? extends Attribute> ae = attrs.getAll(); ae.hasMore();) {
            Attribute attr = ae.next();
            for (NamingEnumeration<?> e = attr.getAll(); e.hasMore();) {
              byte[] sid = (byte[]) e.next();
              sids.add(binarySidToStringSid(sid));
            }
          }
        }
      }
    } catch (NamingException e) {
      LOGGER.log(Level.WARNING, "Failed to retrieve token groups for the user : [" + dn + "]", e);
    } finally {
      if (null != ldapResults) {
        try {
          ldapResults.close();
        } catch (NamingException e) {
          LOGGER.log(Level.WARNING, "Exception during clean up of ldap results", e);
        }
      }
    }
    
    long endTime = System.currentTimeMillis();
    LOGGER.log(Level.INFO, "AD query: base_dn=''{0}'', filter=''{1}'', attrs=''{2}'', time=''{3}''",
        new String[] { dn, LdapConstants.USER_SEARCH_FILTER, Arrays.toString(searchCtls.getReturningAttributes()), (endTime - startTime) + "ms"  });
    LOGGER.log(Level.INFO, "Found ''{0}'' groups sids for user ''{1}'' using TOKEN_GROUPS attribute:\n''{2}''", new Object[] {sids.size(), dn, sids});
    
    return resolveGroupsSidsToSamAccountNames(sids);
	}
	
	/**
	 * Resolve groups objectSids to samAccountNames 
	 * @param sids
	 * @return
	 */
	Set<String> resolveGroupsSidsToSamAccountNames(Set<String> sids) {
    long startTime = System.currentTimeMillis();
    SearchControls searchCtls = new SearchControls();
    searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    searchCtls.setReturningAttributes(new String[] {LdapConstants.ATTRIBUTE_SAMACCOUNTNAME});
    String searchBase = ldapConnectionSettings.getBaseDN();
    
    StringBuffer groupsSearchFilter = new StringBuffer();
    groupsSearchFilter.append("(|");
    for (String sid : sids) {
      groupsSearchFilter.append("(objectSid=" + sid + ")");
    }
    groupsSearchFilter.append(")");
    
    NamingEnumeration<SearchResult> ldapResults = null;
    
    Set<String> samAccountNames = new HashSet<String>(); 
    
    try {
      ldapResults = this.context.search(searchBase, groupsSearchFilter.toString(), searchCtls);
      while (ldapResults.hasMoreElements()) {
        SearchResult sr = ldapResults.next();
        Attributes attrs = sr.getAttributes();
        if (attrs != null) {
          Attribute attr = attrs.get(LdapConstants.ATTRIBUTE_SAMACCOUNTNAME);
          if (attr != null) {
            String samAccountName = (String) attr.get();
            if (samAccountName != null) {
              samAccountNames.add(samAccountName);
            }
          }
        }
      }
    } catch (NamingException e) {
      LOGGER.log(Level.WARNING, "Failed to resolve objectSids to samAccountNames", e);
    } finally {
      if (null != ldapResults) {
        try {
          ldapResults.close();
        } catch (NamingException e) {
          LOGGER.log(Level.WARNING, "Exception during clean up of ldap results", e);
        }
      }
    }
    long endTime = System.currentTimeMillis();
    LOGGER.log(Level.INFO, "AD query: base_dn=''{0}'', filter=''{1}'', attrs=''{2}'', time=''{3}''",
        new String[] { searchBase, groupsSearchFilter.toString(), Arrays.toString(searchCtls.getReturningAttributes()), (endTime - startTime) + "ms"  });
    LOGGER.log(Level.INFO, "Found ''{0}'' groups samAccountNames for ''{1}'' groups sids:\n''{2}''", new Object[] {samAccountNames.size(), sids.size(), samAccountNames});
    
    return samAccountNames;
	}
	
	/**
	 * Read user entry by samAccountName and retrieve
	 * 1. dn attribute (for TOKEN_GROUPS and IN_CHAIN modes)
	 * 2. primary group name (samAccountName for IN_CHAIN mode or dn for RECURSIVE mode)
	 * 3. direct groups dns (for RECURSIVE mode)
	 */
	Set<String> readUserEntry(String userName, ReadAdGroupsType readAdGroupsType, StringBuffer userDn) {
    long startTime = System.currentTimeMillis();
	  List<String> attributes = new ArrayList<String>();
	  if (readAdGroupsType != ReadAdGroupsType.TOKEN_GROUPS) {
	    attributes.add(LdapConstants.ATTRIBUTE_PRIMARY_GROUP_ID);
	    attributes.add(LdapConstants.ATTRIBUTE_OBJECTSID);
	  }
	  if (readAdGroupsType == ReadAdGroupsType.RECURSIVE) {
	    attributes.add(LdapConstants.ATTRIBUTE_MEMBER_OF);
	  }
	  // Create the search controls.
		SearchControls searchCtls = makeSearchCtls(attributes.toArray(new String[] {}));
		// Create the search filter.
		String searchFilter = createSearchFilterForDirectGroups(userName);
		// Specify the Base DN for the search.
		String searchBase = ldapConnectionSettings.getBaseDN();

		Set<String> groups = new HashSet<String>();
		NamingEnumeration<SearchResult> ldapResults = null;
		String dn = null;
		byte[] userSid = null;
		String primaryGroupId = null;
		try {
			ldapResults = this.context.search(searchBase, searchFilter, searchCtls);
			
			if (ldapResults.hasMoreElements()) {
				SearchResult sr = ldapResults.next();
        dn = sr.getNameInNamespace();
				Attributes attrs = sr.getAttributes();
				if (attrs != null) {
          for (NamingEnumeration<? extends Attribute> ae = attrs.getAll(); ae.hasMore();) {
            Attribute attr = ae.next();
            if (attr.getID().equals(LdapConstants.ATTRIBUTE_OBJECTSID)) {
              userSid = (byte[]) attr.get(0);
            } else if (attr.getID().equals(LdapConstants.ATTRIBUTE_PRIMARY_GROUP_ID)) {
              primaryGroupId = (String) attr.get(0);
            } else if (attr.getID().equals(LdapConstants.ATTRIBUTE_MEMBER_OF)){
              for (NamingEnumeration<?> e = attr.getAll(); e.hasMore();) {
                groups.add(e.next().toString());
              }
            }
          }
				}
			}
		} catch (NamingException ne) {
			LOGGER.log(Level.WARNING, "Failed to read AD user entry : [" + userName + "]", ne);
		} finally {
			if (null != ldapResults) {
				try {
					ldapResults.close();
				} catch (NamingException e) {
					LOGGER.log(Level.WARNING, "Exception during clean up of ldap results", e);
				}
			}
		}
		
    long endTime = System.currentTimeMillis();
    LOGGER.log(Level.INFO, "AD query: base_dn=''{0}'', filter=''{1}'', attrs=''{2}'', time=''{3}''",
        new String[] { searchBase, searchFilter, Arrays.toString(searchCtls.getReturningAttributes()), (endTime - startTime) + "ms"  });
    LOGGER.log(Level.INFO, "Retrieved dn=''{0}'', groups=''{1}'' for user ''{2}'' in ''{3}'' mode", new Object[] {dn, groups, userName, readAdGroupsType.toString()});
		
		if (dn == null) {
		  // no user entry
		  return null;
		} else {
		  userDn.append(dn);
		}
		
		if (userSid != null && primaryGroupId != null) {
		  String primaryGroupName = null;
		  if (readAdGroupsType == ReadAdGroupsType.IN_CHAIN) {
		    primaryGroupName = getPrimaryGroupForTheSearchUser(userSid, primaryGroupId, true);
		  }
      if (readAdGroupsType == ReadAdGroupsType.RECURSIVE) {
        primaryGroupName = getPrimaryGroupForTheSearchUser(userSid, primaryGroupId, false);
      }
      if (primaryGroupName != null) {
        groups.add(primaryGroupName);
      }
		}
		
		return groups;
	}

	private SearchControls makeSearchCtls(String attributes[]) {
		SearchControls searchCtls = new SearchControls();
		// Specify the search scope
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		// Specify the attributes to return
		searchCtls.setReturningAttributes(attributes);
		return searchCtls;
	}

	private String createSearchFilterForDirectGroups(String userName) {
		StringBuffer filter;
		filter = new StringBuffer().append(LdapConstants.PREFIX_FOR_DIRECT_GROUPS_FILTER
				+ ldapEscape(userName) + SPConstants.DOUBLE_CLOSE_PARENTHESIS);
		LOGGER.config("search filter value for fetching direct groups :" + filter);
		return filter.toString();
	}

  private String createSearchFilterForInChainQuery(String dn) {
    StringBuffer filter;
    filter = new StringBuffer().append(LdapConstants.LDAP_MATCHING_RULE_IN_CHAIN
        + ldapEscape(dn) + ")");
    LOGGER.config("search filter value for fetching all groups using in_chain AD query:" + filter);
    return filter.toString();
  }

  
	/*
	 * (non-Javadoc)
	 * 
	 * @see com.google.enterprise.connector.sharepoint.ldap.LdapService#
	 * getAllUsersInGroup(java.lang.String, java.util.Set)
	 */
	public void getAllParentGroups(String groupName,
			final Set<String> parentGroupsInfo) {
		if (!Strings.isNullOrEmpty(groupName)) {
			parentGroupsInfo.add(groupName);
			Set<String> parentGroups = getAllParentGroupsForTheGroup(groupName);
			LOGGER.log(Level.INFO, "Parent groups for the group [" + groupName
					+ "] : " + parentGroups);

			for (String group : parentGroups) {
				if (!parentGroupsInfo.contains(group)) {
					getAllParentGroups(group, parentGroupsInfo);
				}
			}
		}
	}

	/**
	 * Returns a set of all parent groups that the search user belongs to.
	 * 
	 * @param groupName is the group, whose parent groups need to be retrieved.
	 * @return a set of all parent groups
	 */
	private Set<String> getAllParentGroupsForTheGroup(String groupName) {
    long startTime = System.currentTimeMillis();
		Set<String> parentGroups = new HashSet<String>();
		// Create the search controls
		SearchControls searchCtls = makeSearchCtls(new String[]{LdapConstants.ATTRIBUTE_MEMBER_OF});
		// Create the search filter
		String searchFilter = createSearchFilterForParentGroups(groupName);
		// Specify the Base DN for the search
		String searchBase = ldapConnectionSettings.getBaseDN();
		NamingEnumeration<SearchResult> ldapResults = null;
		try {
			ldapResults = this.context.search(searchBase, searchFilter, searchCtls);
			while (ldapResults.hasMoreElements()) {
				SearchResult sr = ldapResults.next();
				Attributes attrs = sr.getAttributes();
				if (attrs != null) {
					try {
						for (NamingEnumeration<? extends Attribute> ae = attrs.getAll(); ae.hasMore();) {
							Attribute attr = (Attribute) ae.next();
							for (NamingEnumeration<?> e = attr.getAll(); e.hasMore();) {
								parentGroups.add(e.next().toString());
							}
						}
					} catch (NamingException e) {
						LOGGER.log(Level.WARNING, "Exception while retrieving parent groups for the group ["
								+ groupName + "]", e);
					}
				}
			}
		} catch (NamingException ne) {
			LOGGER.log(Level.WARNING, "Failed to retrieve parent groups for the group name : ["
					+ groupName + "]", ne);
		} finally {
			try {
				if (null != ldapResults) {
					ldapResults.close();
				}
			} catch (NamingException e) {
				LOGGER.log(Level.WARNING, "Exception during clean up of ldap results.", e);
			}
		}
    
		long endTime = System.currentTimeMillis();
    LOGGER.log(Level.INFO, "AD query: base_dn=''{0}'', filter=''{1}'', attrs=''{2}'', time=''{3}''",
        new String[] { searchBase, searchFilter, Arrays.toString(searchCtls.getReturningAttributes()), (endTime - startTime) + "ms"  });
    LOGGER.log(Level.INFO, "Found ''{0}'' parent groups for group ''{1}''", new Object[] {parentGroups.size(), groupName});
		
		return parentGroups;
	}
	
	/**
	 * Escapes special characters used in string literals for LDAP search filters
	 * 
	 * @param literal to be escaped and used in LDAP filter
	 * @return escaped literal 
	 */
	String ldapEscape(String literal) {
		StringBuilder buffer = new StringBuilder(literal.length() * 2);
		for (int i = 0; i < literal.length(); ++i) {
			char c = literal.charAt(i);
			if (LdapConstants.ESCAPE_CHARACTERS.indexOf(c) == -1) {
				buffer.append(c);
			} else {
				String escape = (c < 16) ? "\\0" : "\\";
				buffer.append(escape).append(Integer.toHexString(c));
			}
		}
		return buffer.toString();
	}
	
	private String createSearchFilterForParentGroups(String groupName) {
		StringBuffer filter;
		filter = new StringBuffer().append(LdapConstants.PREFIX_FOR_PARENTS_GROUPS_FILTER
				+ ldapEscape(groupName) + SPConstants.DOUBLE_CLOSE_PARENTHESIS);
		return filter.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.google.enterprise.connector.sharepoint.ldap.LdapService#getAllLdapGroups
	 * (java.lang.String)
	 */
	public Set<String> getAllLdapGroups(String userName) {
		if (Strings.isNullOrEmpty(userName)) {
			return null;
		}
		Set<String> result = null;
		
    ReadAdGroupsType readAdGroupsType = sharepointClientContext.getLdapConnectionSettings().getReadAdGroupsType();
    
    long startTime = System.currentTimeMillis();
    
    // fix me by creating a LDAP connection poll instead of creating context
    // object on demand.
    this.context = new LdapConnection(
        sharepointClientContext.getLdapConnectionSettings()).createContext();
    
    try {
      if (readAdGroupsType == ReadAdGroupsType.TOKEN_GROUPS) {
        // 1. lookup samAccountName -> dn
        StringBuffer dn = new StringBuffer("");
        if( readUserEntry(userName, readAdGroupsType, dn) == null ) {
          // no user entry
          return null;
        }
        // 2. read ldap groups using tokenGroups attribute (returns samAccountNames)
        result = getLdapGroupsUsingTokenGroups(dn.toString());
      }
      if (readAdGroupsType == ReadAdGroupsType.IN_CHAIN) {
        // 1. lookup samAccountName -> dn + retrieve primary group
        StringBuffer dn = new StringBuffer("");
        result = readUserEntry(userName, readAdGroupsType, dn);
        if (result == null) {
          // no user entry
          return null;
        }
        // 2. read ldap groups using IN_CHAIN rule (returns samAccountNames)
        result.addAll(getLdapGroupsUsingInChainQuery(dn.toString()));
      }
      if (readAdGroupsType == ReadAdGroupsType.RECURSIVE) {
        StringBuffer dn = new StringBuffer("");
        // 1. read direct groups + primary group (returns dn-s, need to be resolved to samAccountNames)
        Set<String> groupsDns = readUserEntry(userName, readAdGroupsType, dn);
        if (groupsDns == null) {
          // no user entry
          return null;
        }
        // 2. recursively retrieve all the nested groups
        Set<String> resultGroupsDns = new HashSet<String>();
        for (String groupName : groupsDns) {
          getAllParentGroups(groupName, resultGroupsDns);
        }
        // 3. resolve groups dns to samAccountNames
        result = resolveDnsToSamAccountNames(resultGroupsDns);
      }
    } finally {
      long endTime = System.currentTimeMillis();
      LOGGER.log(Level.INFO, "Found ''{0}'' LDAP groups for user ''{1}'' in ''{2}'' ms", new Object[] { result == null ? 0 : result.size(), userName, (endTime - startTime)});
    }

    return result;
	}

	/**
	 * Retrieves sAMAccountNames for list of entities
	 * @param groups list of distinguishedNames of all groups to resolve
	 * @return sAMAccountName for each of the entities
	 */
	Set<String> resolveDnsToSamAccountNames(Set<String> distinguishedNames) {
    long startTime = System.currentTimeMillis();
		Set<String> result = new HashSet<String>();
		// Create the search controls
		SearchControls searchCtls = makeSearchCtls(
				new String[] {LdapConstants.ATTRIBUTE_SAMACCOUNTNAME});
		// Create the search filter
		StringBuffer filter = new StringBuffer("(|");
		// AD LDAP allows filters up to 10^7 bytes, we will hit issues, we should
		// hit out of memory in parent group resolution before hitting this limit
		for (String dn : distinguishedNames) {
			filter.append(LdapConstants.PREFIX_FOR_GROUP_FILTER)
				  .append(ldapEscape(dn)).append(")");
		}
		filter.append(")");
		// Specify the Base DN for the search
		String searchBase = ldapConnectionSettings.getBaseDN();
		NamingEnumeration<SearchResult> ldapResults = null;
		try {
			ldapResults = this.context.search(
					searchBase, filter.toString(), searchCtls);
			while (ldapResults.hasMoreElements()) {
				SearchResult sr = ldapResults.next();
				Attributes attrs = sr.getAttributes();
				if (attrs != null) {
					try {
						Attribute sAMAccountName = attrs.get(
								LdapConstants.ATTRIBUTE_SAMACCOUNTNAME);
						if (sAMAccountName == null || sAMAccountName.size() == 0) {
							LOGGER.log(Level.WARNING,
									"Could not establish sAMAccountName for [" + sr.getNameInNamespace() + "]");
							continue;
						}
						result.add(sAMAccountName.get(0).toString());
					} catch (NamingException e) {
						LOGGER.log(Level.WARNING, "Exception while retrieving group names. Search filter [" + filter + "]", e);
					}
				}
			}
		} catch (NamingException ne) {
			LOGGER.log(Level.WARNING, "Exception while retrieving group names. Search filter [" + filter + "]", ne);
		} finally {
			try {
				if (null != ldapResults) {
					ldapResults.close();
				}
			} catch (NamingException e) {
				LOGGER.log(Level.WARNING, "Exception during clean up of ldap results.", e);
			}
		}
		
    long endTime = System.currentTimeMillis();
    LOGGER.log(Level.INFO, "AD query: base_dn=''{0}'', filter=''{1}'', attrs=''{2}'', time=''{3}''",
        new String[] { searchBase, filter.toString(), Arrays.toString(searchCtls.getReturningAttributes()), (endTime - startTime) + "ms"  });
    LOGGER.log(Level.INFO, "Found ''{0}'' groups samAccountNames for ''{1}'' groups dns:\n''{2}''", new Object[] {result.size(), distinguishedNames.size(), result});
		
    return result;
	}

	/*
	 * Retrieves SAM account name for the search user for all the possible primary
	 * verification identities sent by GSA and is require to query Directory
	 * service to fetch all direct groups he belongs to. This implementation is
	 * specific to the AD.
	 * 
	 * @param searchUserName search user name.
	 */
	public String getSamAccountNameForSearchUser(final String searchUserName) {
		String tmpUserName = null;
		if (null == searchUserName) {
			return null;
		}
		if (searchUserName.lastIndexOf(SPConstants.AT) != SPConstants.MINUS_ONE) {
			tmpUserName = searchUserName.substring(0, searchUserName.indexOf(SPConstants.AT));
		} else if (searchUserName.indexOf(SPConstants.DOUBLEBACKSLASH) != SPConstants.MINUS_ONE) {
			tmpUserName = searchUserName.substring(searchUserName.indexOf(SPConstants.DOUBLEBACKSLASH) + 1);
		} else {
			tmpUserName = searchUserName;
		}
		return tmpUserName;
	}

	/**
	 * It is a helper method that returns a set of SPGroups for the search user
	 * and the AD groups of which he/she is a direct or indirect member of.
	 * 
	 * @param searchUser the searchUser
	 * @param adGroups a set of AD groups to which search user is a direct of
	 *          indirect member of.
	 */
	private Set<String> getAllSPGroupsForSearchUserAndLdapGroups(
			String searchUser, Set<String> adGroups) {
		StringBuffer groupName;
		// Search user and SP groups memberships found in user data store.
		List<UserGroupMembership> groupMembershipList = null;
		Set<String> spGroups = new HashSet<String>();
		try {
			if (null != this.sharepointClientContext.getUserDataStoreDAO()) {
				groupMembershipList = this.sharepointClientContext.getUserDataStoreDAO().getAllMembershipsForSearchUserAndLdapGroups(adGroups, searchUser);
				for (UserGroupMembership userGroupMembership : groupMembershipList) {
          // append name space to SP groups.
						groupName = new StringBuffer().append(SPConstants.LEFT_SQUARE_BRACKET).append(userGroupMembership.getNamespace()).append(SPConstants.RIGHT_SQUARE_BRACKET).append(userGroupMembership.getGroupName());					
					spGroups.add(groupName.toString());
				}
			}
		} catch (SharepointException se) {
			LOGGER.warning("Exception occured while fetching user groups memberships for the search user ["
					+ searchUser + "] and AD groups [" + adGroups + "]");
		} finally {
			if (null != groupMembershipList) {
				groupMembershipList = null;
			}
		}
		return spGroups;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.google.enterprise.connector.sharepoint.ldap.LdapService#
	 * getAllSearchUserGroups (com.google.enterprise.connector.sharepoint.client.
	 * SharepointClientContext , java.lang.String)
	 */
	public Set<String> getAllGroupsForSearchUser(
			SharepointClientContext sharepointClientContext, String searchUser)
			throws SharepointException {
		ConcurrentHashMap<String, Set<String>> userGroupsMap = new ConcurrentHashMap<String, Set<String>>(
				20);
		Set<String> allUserGroups = new HashSet<String>();
		if (null != searchUser && null != lugCacheStore) {
			if (lugCacheStore.getSize() > 0
					&& lugCacheStore.contains(searchUser.toLowerCase())) {
				userGroupsMap = lugCacheStore.get(searchUser.toLowerCase());
				if (null != userGroupsMap) {
					allUserGroups.addAll(userGroupsMap.get(SPConstants.ADGROUPS));
					allUserGroups.addAll(userGroupsMap.get(SPConstants.SPGROUPS));
				}
				LOGGER.info("Found valid entry for search user [" + searchUser
						+ "] in cache store and he/she is a direct or indirect member of "
						+ allUserGroups.size() + " groups");
				return allUserGroups;
			} else {
				LOGGER.info("No entry found for the user [ "
						+ searchUser
						+ " ] in cache store. Hence querying LDAP server and User data store to fetch all AD and SP groups, to which the search user belongs to.");
				userGroupsMap = getAllADGroupsAndSPGroupsForSearchUser(searchUser);
				if (null != userGroupsMap) {
					allUserGroups.addAll(userGroupsMap.get(SPConstants.ADGROUPS));
					allUserGroups.addAll(userGroupsMap.get(SPConstants.SPGROUPS));

					this.lugCacheStore.put(searchUser.toLowerCase(), userGroupsMap);

	        return allUserGroups;
				} else {
				  return null;
				}

			}
		} else {
			if (Strings.isNullOrEmpty(searchUser)) {
				return null;
			}
			LOGGER.info("The LDAP cache is not yet initialized and hence querying LDAP and User Data Store directly.");
			userGroupsMap = getAllADGroupsAndSPGroupsForSearchUser(searchUser);
			if (userGroupsMap != null) {
			  allUserGroups.addAll(userGroupsMap.get(SPConstants.ADGROUPS));
			  allUserGroups.addAll(userGroupsMap.get(SPConstants.SPGROUPS));
			}
		}
		if (null != userGroupsMap) {
			userGroupsMap = null;
		}
		return allUserGroups;
	}

	/**
	 * Returns a set of groups after adding the specific group name format
	 * provided by connector administrator in the connector configuration page. It
	 * should be called before making a call to user data store to get all SP
	 * groups.
	 * 
	 * @param groupNames set of AD group names.
	 */
	Set<String> addGroupNameFormatForTheGroups(Set<String> groupNames) {
		String format = this.sharepointClientContext.getGroupnameFormatInAce();
		LOGGER.config("Groupname format in ACE : " + format);
		String domain = this.sharepointClientContext.getDomain();
		LOGGER.config("Domain : " + domain);
		Set<String> groups = new HashSet<String>();
		if (format.indexOf(SPConstants.AT) != SPConstants.MINUS_ONE) {
			for (String groupName : groupNames) {
				groups.add(Util.getGroupNameAtDomain(groupName.toLowerCase(), domain.toUpperCase()));
			}
			return groups;
		} else if (format.indexOf(SPConstants.DOUBLEBACKSLASH) != SPConstants.MINUS_ONE) {
			for (String groupName : groupNames) {
				groups.add(Util.getGroupNameWithDomain(groupName.toLowerCase(), domain.toUpperCase()));
			}
			return groups;
		} else {
			for (String groupName : groupNames) {
				groups.add(groupName.toLowerCase());
			}
			return groups;
		}
	}

	/**
	 * Returns the search user name after changing its format to the user name
	 * format specified by the connector administrator during connector
	 * configuration.
	 * 
	 * @param userName
	 */
	String addUserNameFormatForTheSearchUser(final String userName) {
		String format = this.sharepointClientContext.getUsernameFormatInAce();
		LOGGER.config("Username format in ACE : " + format);
		String domain = this.sharepointClientContext.getDomain();
		if (format.indexOf(SPConstants.AT) != SPConstants.MINUS_ONE) {
			return Util.getUserNameAtDomain(userName, domain);
		} else if (format.indexOf(SPConstants.DOUBLEBACKSLASH) != SPConstants.MINUS_ONE) {
			return Util.getUserNameWithDomain(userName, domain);
		} else {
			return userName;
		}
	}

	/**
	 * Create and returns a {@link ConcurrentHashMap} by querying LDAP directory
	 * server to fetch all AD groups that the search user belongs to and then
	 * queries User Data Store with a {@link Set}of AD groups and search user to
	 * fetch all SP groups.
	 * 
	 * @param searchUser the searchUser
	 * @throws SharepointException
	 */
	private ConcurrentHashMap<String, Set<String>> getAllADGroupsAndSPGroupsForSearchUser(
			String searchUser) {
		ConcurrentHashMap<String, Set<String>> userGroupsMap = new ConcurrentHashMap<String, Set<String>>(
				2);
		Set<String> adGroups = null, spGroups = null;
		Set<String> finalADGroups = new HashSet<String>();
		try {
			adGroups = getAllLdapGroups(searchUser);
			if (adGroups == null) {
			  return null;
			}
			if (adGroups.size() > 0) {
				finalADGroups = addGroupNameFormatForTheGroups(adGroups);
			}
			finalADGroups.add("NT AUTHORITY\\authenticated users");
			finalADGroups.add("NT AUTHORITY\\interactive");
			finalADGroups.add("everyone");
			String finalSearchUserName = addUserNameFormatForTheSearchUser(searchUser);
			LOGGER.info("Quering User data store with the AD groups :"
					+ finalADGroups + " and search user [" + finalSearchUserName + "]");
			spGroups = getAllSPGroupsForSearchUserAndLdapGroups(finalSearchUserName, finalADGroups);
			userGroupsMap.put(SPConstants.ADGROUPS, finalADGroups);
			userGroupsMap.put(SPConstants.SPGROUPS, spGroups);
		} finally {
			if (null != adGroups) {
				adGroups = finalADGroups = spGroups = null;
			}
		}
		return userGroupsMap;
	}
}

package org.apache.sshd.client.auth.gss;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.sshd.server.auth.gss.UserAuthGSS;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

public class ClientCredentialHelper {
  
    public static GSSCredential creds(GSSManager mgr, String spn, String keytab) throws LoginException, GSSException {
      
        System.setProperty("java.security.krb5.realm", "HURONC.MERCK.COM");
        System.setProperty("java.security.krb5.kdc","ip-54-40-237-134.huronc.merck.com:88");
        
        LoginContext lc = new LoginContext("x", null, null, new FixedLoginConfiguration(spn, keytab));
    
        lc.login();
        
        GSSName clientName = mgr.createName(spn, GSSName.NT_USER_NAME);
    
        try {
            return (GSSCredential) Subject.doAs(lc.getSubject(), new ClientCredientialsAction(mgr, clientName));
        } catch (PrivilegedActionException e) {
            throw (GSSException) e.getCause();
        }
    }
  
  
    private static class FixedLoginConfiguration extends Configuration {
  
      private AppConfigurationEntry entry;
  
      /**
       * Constructor.
       */
  
      private FixedLoginConfiguration(String spn, String keytab) {
          Map<String, String> parms = new HashMap<String, String>();
  
          parms.put("principal", spn);
          parms.put("useKeyTab", "true");
          parms.put("storeKey", "true");
  
          if (keytab != null) {
              parms.put("keyTab", keytab);
          }
  
          entry = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, parms);
      }
  
      /**
       * Get the configuration entries for a name.
       *
       * @param name The name
       * @return The entries, or <code>null</code> if the name is not known
       */
  
      public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
          return new AppConfigurationEntry[]{entry};
      }
  
      /**
       * Refresh the configuration.  Nothing to do here.
       */
  
      public void refresh() {
      }
  }
    
  /**
   * Privileged action which runs as the subject to get the credentials.
   */

  private static final class ClientCredientialsAction implements PrivilegedExceptionAction<GSSCredential> {

      private GSSManager mgr;
      private GSSName name;

      /**
       * @param mgr The existing GSS manager
       */

      private ClientCredientialsAction(GSSManager mgr, GSSName name) {
          this.mgr = mgr;
          this.name = name;
      }

      /**
       * Do the action.
       *
       * @return The new credentials
       * @throws GSSException If an error occurred
       */

      public GSSCredential run() throws GSSException {
          return mgr.createCredential(name, GSSCredential.INDEFINITE_LIFETIME, UserAuthGSS.KRB5_MECH, GSSCredential.INITIATE_AND_ACCEPT);
      }
  }

}

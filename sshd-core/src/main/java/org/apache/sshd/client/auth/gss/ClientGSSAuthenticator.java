package org.apache.sshd.client.auth.gss;

import static org.apache.sshd.server.auth.gss.UserAuthGSS.KRB5_NT_PRINCIPAL;

import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.security.auth.login.LoginException;

import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

public class ClientGSSAuthenticator extends GSSAuthenticator {
  
  private String clientPrincipal;

  @Override
  public GSSCredential getGSSCredential(GSSManager mgr) throws UnknownHostException, LoginException, GSSException {
    return ClientCredentialHelper.creds(mgr, clientPrincipal, getKeytabFile());
  }
  
  public GSSName getServiceName(GSSManager mgr) throws GSSException{
    return mgr.createName(
        getServicePrincipalName(),
        KRB5_NT_PRINCIPAL);
  }

  public String getClientPrincipal() {
    return clientPrincipal;
  }

  public void setClientPrincipal(String clientPrincipal) {
    this.clientPrincipal = clientPrincipal;
  }
  

}

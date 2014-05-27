package org.apache.sshd.client.auth.gss;

import static org.apache.sshd.server.auth.gss.UserAuthGSS.KRB5_MECH;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuthGSS implements UserAuth {
  
  private final Logger log = LoggerFactory.getLogger(getClass());
  
  private ClientSession session;
  
  private byte[] username;

  private GSSContext context;

  public UserAuthGSS() { }

  public void init(ClientSession session, String service,
      List<Object> identities) throws Exception {
    this.session = session;
    if(session.getUsername() != null) {
      this.username = session.getUsername().getBytes();
    } else {
      throw new NullPointerException("Username cannot be null for client UserAuth");
    }
  }

  public boolean process(Buffer buffer) throws Exception {
    
    ClientGSSAuthenticator auth = getAuthenticator(session);

    // Handle preliminary messages
    if (buffer == null) { // send UserAuth request
      buffer = session.createBuffer((byte) SshConstants.SSH_MSG_USERAUTH_REQUEST);
      buffer.putString(username);
      buffer.putString("ssh-connection".getBytes("UTF-8"));
      buffer.putString("gssapi-with-mic".getBytes("UTF-8"));

      byte[] oidBytes = KRB5_MECH.getDER();
      buffer.putInt(oidBytes.length);
      buffer.putString(oidBytes);

      session.writePacket(buffer);
      
      if(log.isDebugEnabled()){
        log.debug("Sent user auth request with oid {}", KRB5_MECH);
      }

      return Boolean.TRUE;
    } else { // handle next commands
      byte cmd = buffer.getByte();

      if (cmd == SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST && context == null) {

        // consume oid
        byte[] oid = buffer.getStringAsBytes();

        if (!KRB5_MECH.equals(new Oid(oid))) {
          if(log.isDebugEnabled()){
            log.debug("Oid {} not supported.", new Oid(oid));
          }
          return Boolean.FALSE; // oid not supported
        }
        
        GSSManager mgr = auth.getGSSManager();
        GSSCredential creds = auth.getGSSCredential(mgr);

        if (creds == null) {
          return Boolean.FALSE;
        }

        GSSName serviceName = auth.getServiceName(mgr);
        
        context = mgr.createContext(
            serviceName, // target machine
            KRB5_MECH, // 1.2.840.113554.1.2.2
            creds, // client credentials
            GSSContext.DEFAULT_LIFETIME);
        
        context.requestMutualAuth(true);
        context.requestConf(true);
        context.requestInteg(true);
        context.requestCredDeleg(true);
        context.requestReplayDet(false);
        context.requestSequenceDet(false);
        context.requestAnonymity(false);
        
        byte[] tok = new byte[0];

        byte[] out = context.initSecContext(tok, 0, tok.length);

        buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_GSSAPI_TOKEN);
        buffer.putBytes(out);
        session.writePacket(buffer);
        
        if(log.isDebugEnabled()){
          log.debug("Created context and sent initial token of size {}", out.length);
        }
        
        return Boolean.TRUE;
      } else if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
        return Boolean.TRUE;
      } else { // Handle GSS tokens 

        if (context.isEstablished()) {
          sendMIC();
          return Boolean.TRUE;
        } else {
          // Not established - new token to process
          byte[] tok = buffer.getBytes();
          
          if(log.isDebugEnabled()){
            log.debug("Processing token of size {}", tok.length);
          }
          
          byte[] out = context.initSecContext(tok, 0, tok.length);
          boolean established = context.isEstablished();
  
          // Send return token if necessary
          if (out != null && out.length > 0) {
            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_GSSAPI_TOKEN);
            buffer.putBytes(out);
            session.writePacket(buffer);
            return Boolean.TRUE;
          } else if(established){
            sendMIC();
            return Boolean.TRUE;
          } else {
            return Boolean.FALSE;
          }
        }
      }
    }
  }

  private void sendMIC() throws UnsupportedEncodingException, GSSException,
      IOException {
    Buffer buffer;
    byte[] sessionId = ((AbstractSession) session).getSessionId();
    if(log.isDebugEnabled()){
      log.debug("Got session id of size {} for established context", sessionId.length);
    }
    
    Buffer msgbuf = new Buffer();
    
    msgbuf.putString(sessionId);
    msgbuf.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
    msgbuf.putString(username);
    msgbuf.putString("ssh-connection".getBytes("UTF-8"));
    msgbuf.putString("gssapi-with-mic".getBytes("UTF-8"));
 
    MessageProp msgProp = new MessageProp(true);
    byte[] msgBytes = msgbuf.getBytes();
    byte[] mic = context.getMIC(msgBytes, 0,
        msgBytes.length, msgProp);
 
    buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_GSSAPI_MIC);
    buffer.putString(mic);
    session.writePacket(buffer);
  }

  /**
   * Free any system resources used by the module.
   */
  public void destroy() {
    try {
      context.dispose();
    } catch (GSSException e) {
      log.error("Could not dispose of context.", e);
    } finally {
      context = null;
    }
  }
  
  /**
   * Utility to get the configured GSS authenticator for the server, throwing an exception if none is available.
   * Copied from <code>org.apache.sshd.server.auth.gss.UserAuthGSS</code>
   *
   * @param session The current session
   * @return The GSS authenticator
   * @throws Exception If no GSS authenticator is defined
   */
  private ClientGSSAuthenticator getAuthenticator(ClientSession session) throws Exception {
      GSSAuthenticator ga = session.getFactoryManager().getGSSAuthenticator();

      if (ga != null && ga instanceof ClientGSSAuthenticator) {
          return (ClientGSSAuthenticator) ga;
      } else {
          throw new Exception("No GSSAuthenticator configured");
      }
  }
  
  
  
  /**
   * Factory class.
   */
  public static class Factory implements NamedFactory<UserAuth> {
    
    /**
     * Create a new authenticator instance.
     *
     * @return The instance
     */
    public UserAuth create() {
      return new UserAuthGSS();
    }
    
    /**
     * Get the name of the authentication method.
     *
     * @return Tge name, always 'gssapi-with-mic' here.
     */
    public String getName() {
      return "gssapi-with-mic";
    }
    
  }
}
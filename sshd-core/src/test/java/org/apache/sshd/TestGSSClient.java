package org.apache.sshd;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import org.apache.commons.io.output.TeeOutputStream;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.gss.ClientGSSAuthenticator;
import org.apache.sshd.client.auth.gss.UserAuthGSS;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.io.nio2.Nio2ServiceFactoryFactory;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestGSSClient {
  
  private static final Logger LOG = LoggerFactory.getLogger(UserAuthGSSTest.class);
 
  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  
  class SSHClientAction implements PrivilegedAction {

    public Object run() {
      
      try {
        
        // setup client
        SshClient client = SshClient.setUpDefaultClient();
        
        List<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(1);
        userAuthFactories.add(new UserAuthGSS.Factory());
        client.setUserAuthFactories(userAuthFactories);
        
        ClientGSSAuthenticator authenticator = new ClientGSSAuthenticator();
        authenticator.setKeytabFile("/Users/clumjo/Desktop/ingest.keytab");
        authenticator.setClientPrincipal("ingest@HURONC.MERCK.COM");
        authenticator.setServicePrincipalName("host/ip-54-40-237-200.huronc.merck.com@HURONC.MERCK.COM");
        client.setGssAuthenticator(authenticator);
        
        client.setIoServiceFactoryFactory(new Nio2ServiceFactoryFactory());
        
        client.start();
        
        ConnectFuture connFuture = client.connect("ingest", "ip-54-40-237-200.huronc.merck.com", 80).await();
        Assert.assertTrue("Could not connect to server", connFuture.isConnected());
        
        ClientSession session = connFuture.getSession();
        AuthFuture authfuture = session.auth().await();
        Assert.assertTrue("Failed to authenticate to server: " + authfuture.getException(), authfuture.isSuccess());
        
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
  
        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new PipedOutputStream();
        channel.setIn(new PipedInputStream(pipedIn));
        OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open();
  
        teeOut.write("help\n".getBytes());
        teeOut.flush();
        teeOut.close();
  
        channel.waitFor(ClientChannel.CLOSED, 0); // technically this will never work, we need an exit action :)
  
        channel.close(false);
        client.stop();
      
        Assert.assertTrue("Did not receive output", out.toByteArray().length > 0);
      } catch (Exception e) {
        throw new RuntimeException("Failed to ssh into server.", e);
      }
      
      return null;
    }
    
  }
  
  @Test
  public void sshToMerck() throws Throwable {
    
    // Create new loginConf
    File loginConf = testFolder.newFile("login.conf");
    
    String content = "client {" + 
      " com.sun.security.auth.module.Krb5LoginModule required" + 
      " useTicketCache=true" +
      " ticketCache=\"/tmp/ccache\"" +
//      " storeKey=true" + 
//      " useKeyTab=true" + 
//      " principal=\"client@EXAMPLE.COM\"" + 
//      " keyTab=\"" + Resources.getResource("client.keytab").getFile() + "\"" +  
      " debug=true;" + 
    " };\n";
    
    FileWriter fw = new FileWriter(loginConf.getAbsoluteFile());
    BufferedWriter bw = new BufferedWriter(fw);
    bw.write(content);
    bw.close();
    fw.close();
    
    LOG.info("Wrote login.conf {} to file {}", content, loginConf.getAbsoluteFile());
    
    System.setProperty("java.security.auth.login.config", loginConf.getAbsolutePath());
//    System.setProperty("java.security.krb5.realm", "EXAMPLE.COM");
//    System.setProperty("java.security.krb5.kdc","localhost:6089");
    System.setProperty("sun.security.krb5.debug", "true");
//    System.setProperty("java.security.krb5.conf", Resources.getResource("krb5.conf").getFile() );
    
//    LoginContext lc = new LoginContext("client");
//    lc.login();
//    Subject.doAs(lc.getSubject(), new SSHClientAction());
    
    SSHClientAction action = new SSHClientAction();
    action.run();
  }
}

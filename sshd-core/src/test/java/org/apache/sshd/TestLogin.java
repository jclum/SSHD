package org.apache.sshd;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.security.PrivilegedAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestLogin {
  
  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  
  private static final Logger LOG = LoggerFactory.getLogger(TestLogin.class);
  
  class TestAction implements PrivilegedAction {

    public Object run() {
      return "Success";
    }
  }
  
  @Test
  public void testLogin() throws Throwable {
    // Create new loginConf
    File loginConf = testFolder.newFile("login.conf");
    
    String content = "client {" + 
      " com.sun.security.auth.module.Krb5LoginModule required" + 
      " storeKey=true" + 
      " useKeyTab=true" + 
      " principal=\"ingest@HURONC.MERCK.COM\"" + 
      " keyTab=\"/Users/clumjo/Desktop/ingest.keytab\"" +  
      " debug=true;" + 
    " };\n";
    
    FileWriter fw = new FileWriter(loginConf.getAbsoluteFile());
    BufferedWriter bw = new BufferedWriter(fw);
    bw.write(content);
    bw.close();
    fw.close();
    
    LOG.info("Wrote login.conf {} to file {}", content, loginConf.getAbsoluteFile());
    
    System.setProperty("java.security.auth.login.config", loginConf.getAbsolutePath());
    System.setProperty("java.security.krb5.realm", "HURONC.MERCK.COM");
    System.setProperty("java.security.krb5.kdc","ip-54-40-237-134.huronc.merck.com:88");
    System.setProperty("sun.security.krb5.debug", "true");
//    System.setProperty("java.security.krb5.conf", Resources.getResource("krb5.conf").getFile() );
    
    LoginContext lc = new LoginContext("client");
    lc.login();
    System.out.println(Subject.doAs(lc.getSubject(), new TestAction()));
    
  }

}

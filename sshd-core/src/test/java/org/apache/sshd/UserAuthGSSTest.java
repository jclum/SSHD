package org.apache.sshd;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.InetAddress;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.apache.commons.io.output.TeeOutputStream;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.kerberos.client.KdcConfig;
import org.apache.directory.kerberos.client.KdcConnection;
import org.apache.directory.kerberos.client.TgTicket;
import org.apache.directory.server.annotations.CreateChngPwdServer;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.kerberos.kdc.KerberosTestUtils;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.codec.types.PrincipalNameType;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.gss.UserAuthGSS;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@RunWith(FrameworkRunner.class)
@CreateDS(name = "KdcConnectionTest-class", enableChangeLog = false,
    partitions =
        {
            @CreatePartition(
                name = "example",
                suffix = "dc=example,dc=com",
                contextEntry=@ContextEntry( entryLdif = 
                    "dn: dc=example,dc=com\n" +
                    "objectClass: domain\n" +
                    "dc: example" ) )
    },
    additionalInterceptors =
        {
            KeyDerivationInterceptor.class
    })
@CreateLdapServer(
    transports =
        {
            @CreateTransport(address="localhost", protocol = "LDAP")
    })
@CreateKdcServer(
    searchBaseDn = "dc=example,dc=com",
    transports =
        {
            @CreateTransport(address="localhost", protocol = "TCP", port = 6089),
            @CreateTransport(protocol = "UDP")
    },
    chngPwdServer = @CreateChngPwdServer
    (
        transports =
        {
            @CreateTransport(address="localhost", protocol = "TCP", port = 6090),
            @CreateTransport(protocol = "UDP")
        }    
    ))
@ApplyLdifs({
  
    // client
    "dn: uid=client,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: client",
    "sn: client",
    "uid: client",
    "userPassword: randall",
    "krb5PrincipalName: client@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0",
  
    // ssh
    "dn: uid=ssh,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: SSH Service",
    "sn: Service",
    "uid: ssh",
    "userPassword: randall",
    "krb5PrincipalName: ssh/localhost@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0",
  
    // krbtgt
    "dn: uid=krbtgt,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: KDC Service",
    "sn: Service",
    "uid: krbtgt",
    "userPassword: randall",
    "krb5PrincipalName: krbtgt/EXAMPLE.COM@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0",
    
    // changepwd
    "dn: uid=kadmin,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: changepw Service",
    "sn: Service",
    "uid: kadmin",
    "userPassword: randall",
    "krb5PrincipalName: kadmin/changepw@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0",

    // app service
    "dn: uid=ldap,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: LDAP",
    "sn: Service",
    "uid: ldap",
    "userPassword: randall",
    "krb5PrincipalName: ldap/localhost@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0"
})
/**
 * SSH Deployment Contributor Test
 * 
 * Setting up LDAP, KDC, SSH Provider, and client to test the "help" command
 */
public class UserAuthGSSTest extends AbstractLdapTestUnit {
  
    private static final Logger LOG = LoggerFactory.getLogger(UserAuthGSSTest.class);
  
    public static final String USERS_DN = "dc=example,dc=com";
    
    private static String PASSWORD = "randall";
    
    
    private static String clientID = "client";
    private static String clientPrincipal = "client@EXAMPLE.COM";
    private static String sshPrincipal;
    
    private static KdcConnection conn;
    
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Before
    public void setup() throws Throwable {
        kdcServer.setSearchBaseDn( USERS_DN );
        if ( conn == null ) {
          
          kdcServer.getConfig().setEncryptionTypes(Collections.singleton(EncryptionType.DES_CBC_MD5));
          
          if(LOG.isDebugEnabled()){
            LOG.debug("Encryption types {}", kdcServer.getConfig().getEncryptionTypes());
          }

          KdcConfig config = KdcConfig.getDefaultConfig();
          config.setUseUdp( false );
          config.setKdcPort( kdcServer.getTcpPort() );
          config.setPasswdPort( kdcServer.getChangePwdServer().getTcpPort() );
          config.setEncryptionTypes( kdcServer.getConfig().getEncryptionTypes() );          
          config.setTimeout( Integer.MAX_VALUE );
          conn = new KdcConnection( config );
        }

        String ldapPrincipal = KerberosTestUtils.fixServicePrincipalName( "ldap/localhost@EXAMPLE.COM", new Dn(
            "uid=ldap,dc=example,dc=com" ), getLdapServer() );
        LOG.info("LDAP principal {}", ldapPrincipal);
        
        sshPrincipal = KerberosTestUtils.fixServicePrincipalName( "ssh/localhost@EXAMPLE.COM", new Dn(
            "uid=ssh,dc=example,dc=com" ), getLdapServer() );

        LOG.info("SSH principal {} Canonical name {}", sshPrincipal, InetAddress.getLocalHost().getCanonicalHostName());
    }
    
    public class KeytabGenerator {

      public KeytabGenerator() {
      }

      public String getKeytab() throws Exception {
        
        TgTicket tgt = conn.getTgt("client@EXAMPLE.COM", "randall");

        Keytab kt = new Keytab();
        KeytabEntry ke = new KeytabEntry(tgt.getClientName() + "@"
            + tgt.getRealm(), PrincipalNameType.KRB_NT_PRINCIPAL.getValue(),
            new KerberosTime(tgt.getStartTime()), (byte) tgt.getSessionKey()
                .getKeyVersion(), tgt.getSessionKey());

        kt.setEntries(Collections.singletonList(ke));

        File keytabFile = testFolder.newFile();

        kt.write(keytabFile);

        return keytabFile.getAbsolutePath();
      }

    }

    public class SSHServerGSSAction implements PrivilegedAction {
      
      private final Thread shutdownHandler = new Thread() {
        public void run() {
          if (sshd != null) {
            try {
              sshd.stop(true);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          }
        };
      };

      private int port;
      private String keytabLocation;
      
      private SshServer sshd;
      
      public SSHServerGSSAction(String keytabLocation, int port) {
        this.port = port;
        this.keytabLocation = keytabLocation;
      }
      
      public Object run() {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        List<NamedFactory<org.apache.sshd.server.UserAuth>> userAuthFactories = new ArrayList<NamedFactory<org.apache.sshd.server.UserAuth>>(1);
        userAuthFactories.add(new org.apache.sshd.server.auth.gss.UserAuthGSS.Factory());
        sshd.setUserAuthFactories(userAuthFactories);

        GSSAuthenticator authenticator = new GSSAuthenticator();
        authenticator.setKeytabFile(keytabLocation);
        sshd.setGSSAuthenticator(authenticator);
        int workers = 1;
        if (workers > 0) {
          sshd.setNioWorkers(workers);
        }
        sshd.setShellFactory(new ProcessShellFactory(new String[] { "ls" }));
        try {
          sshd.start();
        } catch (IOException e) {
          throw new RuntimeException("Failed to start SSH Server", e);
        } finally {
          Runtime.getRuntime().addShutdownHook(shutdownHandler);
        }
        return null;
      }
    }
    
    public class SSHClientGSSAction implements PrivilegedAction {
      
      private String keytabLocation;
      private String username;
      private String host;
      private int port;

      public SSHClientGSSAction(String keytabLocation, String username, String host, int port){
        this.keytabLocation = keytabLocation;
        this.username = username;
        this.host = host;
        this.port = port;
      }

      public Object run() {
        
        try {
          
          // setup client
          SshClient client = SshClient.setUpDefaultClient();
          
          List<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(1);
          userAuthFactories.add(new UserAuthGSS.Factory());
          
          client.setUserAuthFactories(userAuthFactories);
          
          client.start();
          
          ConnectFuture connFuture = client.connect(username, host, port).await();
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
    
          teeOut.write("ls\n".getBytes());
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
    
    public class KinitAction implements PrivilegedAction {

      public Object run() {
        return "SUCCESS!";
      }

    }

    private static class FixedLoginConfiguration extends Configuration {

      private AppConfigurationEntry entry;
      
      private FixedLoginConfiguration(String spn, String keytab) {
        Map<String, String> parms = new HashMap<String, String>();

//        parms.put("isInitiator", "false");
        parms.put("principal", spn);
        parms.put("useKeyTab", "true");
        parms.put("storeKey", "true");

        if (keytab != null) {
          parms.put("keyTab", keytab);
        }

        entry = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, parms);
      }

      public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        return new AppConfigurationEntry[] { entry };
      }

      public void refresh() {
      }
    }
    
    @Test
    public void testConnection() throws Throwable {
      
      String sshHost = "localhost";
      int sshPort = 6091;
      String clientUsername = "client";
      
      KeytabGenerator keytabGenerator = new KeytabGenerator();
      String clientKeytabLocation = keytabGenerator.getKeytab();
      
      KinitAction action = new KinitAction();

      LoginContext lc = new LoginContext("x", null, null, new FixedLoginConfiguration("hnelson@EXAMPLE.COM", clientKeytabLocation));

      lc.login();

      System.out.println(Subject.doAs(lc.getSubject(), action));
      
//      SSHServerGSSAction server = new SSHServerGSSAction(sshHost, sshPort);
//      SSHClientGSSAction client = new SSHClientGSSAction(clientKeytabLocation, clientUsername, sshHost, sshPort);
//      
//      server.run();
//      client.run();

    }

}
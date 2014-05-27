package org.apache.sshd;

import java.io.File;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.apache.directory.kerberos.client.KdcConfig;
import org.apache.directory.kerberos.client.KdcConnection;
import org.apache.directory.kerberos.client.TgTicket;
import org.apache.directory.server.annotations.CreateChngPwdServer;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.kerberos.kdc.AbstractKerberosITest;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.codec.types.PrincipalNameType;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateDS(name = "KerberosTcpIT-class",
    partitions =
        {
            @CreatePartition(
                name = "example",
                suffix = "dc=example,dc=com")
    },
    additionalInterceptors =
        {
            KeyDerivationInterceptor.class
    })
@CreateLdapServer(
    transports =
        {
            @CreateTransport(protocol = "LDAP")
    })
@CreateKdcServer(
    searchBaseDn = "dc=example,dc=com",
    transports =
        {
            @CreateTransport(protocol = "TCP", port = 6086)
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
  
  "dn: dc=example,dc=com",
  "objectClass: top",
  "objectClass: domain",
  "dc: example",

  "dn: ou=users,dc=example,dc=com",
  "objectClass: top",
  "objectClass: organizationalUnit",
  "ou: users",
  
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
//  "dn: uid=krbtgt,dc=example,dc=com",
//  "objectClass: top",
//  "objectClass: person",
//  "objectClass: inetOrgPerson",
//  "objectClass: krb5principal",
//  "objectClass: krb5kdcentry",
//  "cn: KDC Service",
//  "sn: Service",
//  "uid: krbtgt",
//  "userPassword: randall",
//  "krb5PrincipalName: krbtgt/EXAMPLE.COM@EXAMPLE.COM",
//  "krb5KeyVersionNumber: 0",
  
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
//  "dn: uid=ldap,dc=example,dc=com",
//  "objectClass: top",
//  "objectClass: person",
//  "objectClass: inetOrgPerson",
//  "objectClass: krb5principal",
//  "objectClass: krb5kdcentry",
//  "cn: LDAP",
//  "sn: Service",
//  "uid: ldap",
//  "userPassword: randall",
//  "krb5PrincipalName: ldap/localhost@EXAMPLE.COM",
//  "krb5KeyVersionNumber: 0"
})
public class UserAuthGSSTest2 extends AbstractKerberosITest {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  public class KeytabGenerator {

    public KeytabGenerator() {
    }

    public String getKeytab() throws Exception {

      KdcConfig config = new KdcConfig();
      config.setUseUdp( false );
      config.setKdcPort( kdcServer.getTcpPort() );
      config.setPasswdPort( kdcServer.getChangePwdServer().getTcpPort() );
      config.setEncryptionTypes( kdcServer.getConfig().getEncryptionTypes() );          
      config.setTimeout( Integer.MAX_VALUE );

      KdcConnection kdcCon = new KdcConnection(config);
      TgTicket tgt = kdcCon.getTgt("client@EXAMPLE.COM", "randall");

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

  public class KinitAction implements PrivilegedAction {

    public Object run() {
      return "SUCCESS!";
    }

  }

  private static class FixedLoginConfiguration extends Configuration {

    private AppConfigurationEntry entry;
    
    private FixedLoginConfiguration(String spn, String keytab) {
      Map<String, String> parms = new HashMap<String, String>();

//      parms.put("isInitiator", "false");
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

    KeytabGenerator keytabGenerator = new KeytabGenerator();
    String clientKeytabLocation = keytabGenerator.getKeytab();

    KinitAction action = new KinitAction();

    LoginContext lc = new LoginContext("x", null, null, new FixedLoginConfiguration("hnelson@EXAMPLE.COM", clientKeytabLocation));

    lc.login();

    System.out.println(Subject.doAs(lc.getSubject(), action));

    // SSHServerGSSAction server = new SSHServerGSSAction(sshHost, sshPort);
    // SSHClientGSSAction client = new SSHClientGSSAction(clientKeytabLocation,
    // clientUsername, sshHost, sshPort);

    // server.run();
    // client.run();

  }

}
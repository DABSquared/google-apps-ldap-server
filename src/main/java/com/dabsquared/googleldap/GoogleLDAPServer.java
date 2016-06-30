package com.dabsquared.googleldap;

import com.google.api.services.admin.directory.model.User;
import com.google.api.services.admin.directory.model.Users;
import org.apache.commons.io.FileUtils;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.loader.JarLdifSchemaLoader;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.authn.Authenticator;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import java.io.File;
import java.io.FileReader;
import java.text.MessageFormat;
import java.util.Properties;
import java.util.ResourceBundle;

import java.io.*;
import java.text.MessageFormat;
import java.util.*;

import static org.apache.directory.server.core.integ.AbstractLdapTestUnit.service;


/**
 * Created by daniel on 6/28/16.
 */
public class GoogleLDAPServer {
    private static final Logger log = LogManager.getLogger(GoogleLDAPServer.class);

    private File workDir = null;

    private DirectoryService service;
    private LdapServer server;

    private String domain;

    public GoogleLDAPServer(File workDir, String domain) {
        this.workDir = workDir;
        this.domain = domain;
        // Initialize the LDAP service
        try {
            service = new DefaultDirectoryService();
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            this.loadSchemas();
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            this.loadDirectoryService();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    private void loadSchemas() throws Exception
    {
        log.debug("Starting to load the schema.");
        File schemaRepository = new File(workDir, "schema");

        SchemaManager schemaManager = new DefaultSchemaManager();
        schemaManager.loadAllEnabled();
        service.setSchemaManager(schemaManager);


        SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        service.setSchemaPartition(schemaPartition);


        // Init the LdifPartition
        LdifPartition ldifPartition = new LdifPartition(service.getSchemaManager(), service.getDnFactory());
        ldifPartition.setPartitionPath(schemaRepository.toURI());

        schemaPartition.setWrappedPartition(ldifPartition);
        service.setInstanceLayout(new InstanceLayout(this.workDir));


        // We have to load the schema now, otherwise we won't be able
        // to initialize the Partitions, as we won't be able to parse
        // and normalize their suffix DN
        schemaManager.loadAllEnabled();



        List<Throwable> errors = schemaManager.getErrors();

        if (errors.size() != 0) {
            throw new Exception(errors.toString());
        }
        log.debug("Loaded the schema.");

        // then the system partition
        // this is a MANDATORY partition
        log.debug("Loading the system partition.");

        JdbmPartition partition = new JdbmPartition(service.getSchemaManager(), service.getDnFactory());
        partition.setId("system");
        partition.setPartitionPath(new File(this.workDir, "system").toURI());
        partition.setSuffixDn(new Dn(ServerDNConstants.SYSTEM_DN));
        service.setSystemPartition(partition);
        log.debug("Loaded the system partition.");
    }



    private void loadDirectoryService() throws Exception
    {
        // Disable the ChangeLog system
        service.getChangeLog().setEnabled(false);
        service.setDenormalizeOpAttrsEnabled(false);


        //Disable Anoymous Access
        //service.setAccessControlEnabled(true);
        service.setAllowAnonymousAccess(true);

        List<Interceptor> interceptors = service.getInterceptors();

        for (Interceptor interceptor : interceptors) {
            if (interceptor instanceof AuthenticationInterceptor) {
                log.debug("" + interceptor.getName());
                AuthenticationInterceptor ai = (AuthenticationInterceptor) interceptor;
                Set<Authenticator> auths = new HashSet<Authenticator>();
                //auths.add(new CrowdAuthenticator(m_CrowdClient, service)); //TODO: Make a google authenticator
                ai.setAuthenticators(auths);
            }
        }

        GooglePartition googlePartition = new GooglePartition(domain);
        googlePartition.setId("google");
        googlePartition.setSchemaManager(service.getSchemaManager());
        googlePartition.initialize();
        service.addPartition(googlePartition);

        // And start the service
        service.startup();
    }


    /**
     * Starts the LdapServer
     *
     * @throws Exception if starting the LDAP server does not work.
     */
    public void startServer() throws Exception {
        server = new LdapServer();
        int serverPort = 10389;

        Transport t = new TcpTransport(serverPort);

        //SSL Support
        boolean sslEnabled = false;

        if(sslEnabled) {
            String keyStore = "etc/ldap-server.keystore";
            String password = "changeit";

            t.setEnableSSL(true);
            server.setKeystoreFile(keyStore);
            server.setCertificatePassword(password);
            server.addExtendedOperationHandler(new StartTlsHandler());

        }

        server.setTransports(t);
        server.setDirectoryService(service);
        server.start();
    }







    /**
     * Main application method.
     *
     * @param args not used.
     */
    public static void main(String[] args) {
        try {

            File workDir = new File("work");
            if(workDir.exists()) {
                FileUtils.deleteDirectory(workDir);
            }
            workDir.mkdirs();

            // Create the server
            GoogleLDAPServer googleLDAPServer = new GoogleLDAPServer(workDir, "klinche.com");

            // Start the server
            googleLDAPServer.startServer();
        } catch (Exception e) {
            log.error("main()", e);
        }
    }
}

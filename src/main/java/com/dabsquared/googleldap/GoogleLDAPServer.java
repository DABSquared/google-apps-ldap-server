package com.dabsquared.googleldap;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.Strings;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.entry.ClonedServerEntry;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.authn.Authenticator;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;
import org.apache.directory.server.protocol.shared.store.LdifLoadFilter;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mortbay.util.IO;


import java.io.File;

import java.io.FileFilter;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;


/**
 * Created by daniel on 6/28/16.
 */
public class GoogleLDAPServer {
    private static final Logger log = LogManager.getLogger(GoogleLDAPServer.class);

    private File workDir = null;
    private DirectoryService service;
    private LdapServer server;
    private File ldifDirectory;
    private String domain;
    private final List<LdifLoadFilter> ldifFilters = new ArrayList();

    public GoogleLDAPServer(File workDir, String domain) {
        this.workDir = workDir;
        this.domain = domain;
        this.ldifDirectory = new File("ldifs");

        // Initialize the LDAP service
        try {
            service = new DefaultDirectoryService();
            this.loadSchemas();
            this.loadDirectoryService();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    private void loadSchemas() throws Exception
    {
        log.debug("Starting to load the schema.");
        service.setInstanceLayout(new InstanceLayout(this.workDir));
        String workingDirectory = service.getInstanceLayout().getPartitionsDirectory().getPath();

        // Extract the schema on disk (a brand new one) and load the registries
        File schemaRepository = new File(workingDirectory, "schema");
        SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(new File(workingDirectory));
        extractor.extractOrCopy(true);



//        ArrayList<String> files = new ArrayList<String>();
//        files.add("/schema/ou=schema/cn=rfc2307bis/ou=attributetypes/m-oid=1.3.6.1.1.1.1.0.ldif");
//
//        for(String filename : files) {
//            String source = "/partitions" + filename;
//            String destname = "work/partitions" + filename;
//            URL inputUrl = getClass().getResource(source);
//            File dest = new File(destname);
//            FileUtils.copyURLToFile(inputUrl, dest);
//        }

        File folder = new File("work/partitions/schema/ou=schema");
        File[] listOfFiles = folder.listFiles();

        ArrayList<File> files = new ArrayList<File>();

        for (int i = 0; i < listOfFiles.length; i++) {
            if (listOfFiles[i].isFile()) {
                files.add(listOfFiles[i]);
            }
        }

        Charset charset = StandardCharsets.UTF_8;
        for(File file : files) {
            String content = new String(Files.readAllBytes(file.toPath()), charset);
            content = content.replaceAll("m-disabled: TRUE", "m-disabled: FALSE");
            Files.write(file.toPath(), content.getBytes(charset));
        }

        SchemaLoader loader = new LdifSchemaLoader(schemaRepository);
        SchemaManager schemaManager = new DefaultSchemaManager(loader);

        schemaManager.loadAllEnabled();
        service.setSchemaManager(schemaManager);


        SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        service.setSchemaPartition(schemaPartition);


        // Init the LdifPartition
        LdifPartition ldifPartition = new LdifPartition(service.getSchemaManager(), service.getDnFactory());
        ldifPartition.setPartitionPath(schemaRepository.toURI());

        schemaPartition.setWrappedPartition(ldifPartition);


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
                auths.add(new GoogleAuthenticator(AuthenticationLevel.SIMPLE, this.domain)); //TODO: Make a google authenticator
                ai.setAuthenticators(auths);
            }
        }

        GooglePartition googlePartition = new GooglePartition(domain);
        googlePartition.setId("klinche");
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
            GoogleLDAPServer googleLDAPServer = new GoogleLDAPServer(workDir, args[0]);

            // Start the server
            googleLDAPServer.startServer();
        } catch (Exception e) {
            log.error("main()", e);
        }
    }




}

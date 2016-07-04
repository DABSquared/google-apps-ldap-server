package com.dabsquared.googleldap;

import com.google.api.services.admin.directory.Directory;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.authn.AbstractAuthenticator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.mail.Session;
import javax.mail.Store;
import java.util.Properties;

/**
 * Created by daniel on 7/3/16.
 */
public class GoogleAuthenticator extends AbstractAuthenticator {

    private static final Logger log = LogManager.getLogger(GooglePartition.class);

    private String domain = null;

    protected GoogleAuthenticator(AuthenticationLevel type, String domain) {
        super(type);
        this.domain = domain;
    }

    protected GoogleAuthenticator(AuthenticationLevel type, Dn baseDn) {
        super(type, baseDn);
    }

    public LdapPrincipal authenticate(BindOperationContext bindOperationContext) throws Exception {

        Properties props = System.getProperties();
        props.setProperty("mail.store.protocol", "imaps");

        String user = bindOperationContext.getDn().getRdn(0).getNormValue();
        String pass = new String(bindOperationContext.getCredentials(),"utf-8");

        if (user.split("@").length == 1) {
            user = user + "@" + this.domain;
        }

        if (!this.domain.equals(user.split("@")[1])) {
            throw new javax.naming.AuthenticationException("Invalid domain for user: " + user);
        }


        final Properties properties = new Properties();
        properties.put("mail.imap.ssl.enable", "true");

        Session imapSession = Session.getInstance(properties, null);
        imapSession.setDebug(false);
        Store imapStore = imapSession.getStore("imap");

        imapStore.connect("imap.gmail.com", user, pass);

        boolean works = imapStore.isConnected();
        imapStore.close();

        try {
            if(!works) {
                log.debug("()::Authentication failed");
                throw new javax.naming.AuthenticationException("Invalid credentials for user: " + user);
            } else {
                log.debug("Authed " + user);
                return new LdapPrincipal(this.getDirectoryService().getSchemaManager(), bindOperationContext.getDn(), AuthenticationLevel.SIMPLE);
            }
        } catch (Exception ex) {
            log.debug("()::Authentication failed: " + ex);
            throw new javax.naming.NamingException("Unable to perform authentication: " + ex);
        }
    }
}

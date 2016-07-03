package com.dabsquared.googleldap;

import com.google.api.client.util.ArrayMap;
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.model.*;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.*;


import java.io.IOException;
import java.util.*;

import static java.lang.Math.abs;
import static javax.naming.directory.DirContext.REPLACE_ATTRIBUTE;

/**
 * Created by daniel on 6/28/16.
 */
public class GoogleLDAPSync {
    private static final Logger log = LogManager.getLogger(GoogleLDAPSync.class);

    DirContext ctx = null;

    private String rootCn;

    public GoogleLDAPSync(String bindDn, String bindPassword, String ldapServer, int port, String rootCn) {
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + ldapServer + ":" + port);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL,bindDn); // specify the username
        env.put(Context.SECURITY_CREDENTIALS, bindPassword);// specify the password
        this.rootCn = rootCn;
        try {
            ctx = new InitialDirContext(env);
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }


    public void sync()
    {
        GoogleDirectoryService googleService = new GoogleDirectoryService();
        Directory service = null;
        try {
            service = googleService.getDirectoryService();
        } catch (IOException e) {
            e.printStackTrace();
        }

        List<User> result = null;
        try {
            result = service.users().list()
                    .setCustomer("my_customer")
                    .setOrderBy("email")
                    .setProjection("full")
                    .execute().getUsers();
        } catch (IOException e) {
            e.printStackTrace();
        }

        for (User user: result) {
            this.addUser(user, service);
        }

        // Print the first 10 users in the domain.
        List<Group> groups = null;
        try {
            groups = service.groups().list().setCustomer("my_customer").execute().getGroups();
        } catch (IOException e) {
            e.printStackTrace();
        }

        for (Group group: groups) {
            this.addGroup(group, service, result);
        }
    }

    public void addGroup(Group group, Directory service, List<User> users)
    {
        String groupname = group.getEmail().split("@")[0];

        String entryDN = "cn=" + groupname + ", ou=groups, dc=" + this.rootCn + ", dc=com";

        Attribute[] attributes = new Attribute[10];


        // entry's attributes
        attributes[0] = new BasicAttribute(SchemaConstants.GID_NUMBER_AT, "" + abs(group.getId().hashCode()));

        if (group.getDescription() != null && !group.getDescription().equals("")) {
            attributes[1] = new BasicAttribute(SchemaConstants.DESCRIPTION_AT, group.getDescription());
        }

        // Print the first 10 users in the domain.
        List<Member> members = null;
        try {
            members = service.members().list(group.getId()).execute().getMembers();
        } catch (IOException e) {
            e.printStackTrace();
        }

        attributes[1] = new BasicAttribute(SchemaConstants.MEMBER_UID_AT);

        for (Member member: members) {
            if (member.getEmail() == null) {
                for(User user : users) {
                    String uuid = user.getPrimaryEmail().split("@")[0];
                    attributes[1].add(uuid);
                }
            } else {
                String uuid = member.getEmail().split("@")[0];
                attributes[1].add(uuid);
            }
        }

        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("posixGroup");

        // build the entry
        BasicAttributes entry = new BasicAttributes();
        entry.put(oc);

        for (Attribute attr: attributes) {
            if(attr != null) {
                entry.put(attr);
            }
        }
        entry.put(oc);

        // Add the entry
        try {
            ctx.createSubcontext(entryDN, entry);
        } catch (NamingException e) {
            try {
                ctx.modifyAttributes(entryDN, REPLACE_ATTRIBUTE, entry);
            } catch (NamingException e1) {
                e1.printStackTrace();
            }
        }
    }

    public void addUser(User user, Directory service)
    {
        String username = user.getPrimaryEmail().split("@")[0];

        String entryDN = "cn=" + username + ", ou=users, dc=" + this.rootCn + ", dc=com";

        Attribute[] attributes = new Attribute[10];

        // entry's attributes
        attributes[0] = new BasicAttribute(SchemaConstants.CN_AT, user.getName().getFullName());
        attributes[1] = new BasicAttribute(SchemaConstants.SN_AT, user.getName().getFamilyName());
        attributes[2] = new BasicAttribute(SchemaConstants.GIVENNAME_AT, user.getName().getGivenName());
        attributes[3] = new BasicAttribute(SchemaConstants.MAIL_AT, user.getPrimaryEmail());
        attributes[4] = new BasicAttribute(SchemaConstants.UID_NUMBER_AT, user.getId());
        attributes[5] = new BasicAttribute(SchemaConstants.GID_NUMBER_AT, user.getId());
        attributes[6] = new BasicAttribute(SchemaConstants.UID_AT, username);
        attributes[7] = new BasicAttribute(SchemaConstants.HOME_DIRECTORY_AT, "/test");

        List <ArrayMap> phones = (List<ArrayMap>) user.getPhones();
        if (phones != null) {
            for (ArrayMap phone: phones) {
                if (phone.get("type").equals("mobile")) {
                    attributes[8] = new BasicAttribute(SchemaConstants.MOBILE_TELEPHONE_NUMBER_AT, phone.get("value"));
                } else if (phone.get("type").equals("work")) {
                    attributes[9] = new BasicAttribute(SchemaConstants.TELEPHONE_NUMBER_AT, phone.get("value"));
                }
            }
        }


        List <ArrayMap> emails = (List<ArrayMap>) user.getEmails();
        if (emails != null) {
            for (ArrayMap email: emails) {
                attributes[3].add(email.get("value"));
            }
        }

        // Print the first 10 users in the domain.
        List<ArrayMap> aliases = null;
        try {
            aliases = (List<ArrayMap>)(Object) service.users().aliases().list(user.getPrimaryEmail()).execute().getAliases();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (aliases != null) {
            for (ArrayMap alias : aliases) {
                attributes[3].add(alias.get("alias"));
            }
        }

        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("person");
        oc.add("organizationalPerson");
        oc.add("inetOrgPerson");
        oc.add("posixAccount");

        // build the entry
        BasicAttributes entry = new BasicAttributes();
        entry.put(oc);

        for (Attribute attr: attributes) {
            if(attr != null) {
                entry.put(attr);
            }
        }
        entry.put(oc);

        // Add the entry
        try {
            ctx.createSubcontext(entryDN, entry);
        } catch (NamingException e) {
            try {
                entry.remove(SchemaConstants.CN_AT);
                ctx.modifyAttributes(entryDN, REPLACE_ATTRIBUTE, entry);
            } catch (NamingException e1) {
                e1.printStackTrace();
            }
        }
    }



    /**
     * Main application method.
     *
     * @param args not used.
     */
    public static void main(String[] args) {
        try {
            // Create the server sync
            GoogleLDAPSync googleLDAPSync = new GoogleLDAPSync(args[0], args[1], args[2], Integer.parseInt(args[3]), args[4]);
            googleLDAPSync.sync();

        } catch (Exception e) {
            log.error("main()", e);
        }
    }
}

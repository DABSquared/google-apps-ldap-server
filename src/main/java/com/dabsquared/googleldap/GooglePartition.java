package com.dabsquared.googleldap;

import com.dabsquared.googleldap.util.LRUCacheMap;
import com.google.api.client.util.ArrayMap;
import com.google.api.services.admin.directory.model.User;
import com.google.api.services.admin.directory.model.Users;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.EmptyCursor;
import org.apache.directory.api.ldap.model.cursor.ListCursor;
import org.apache.directory.api.ldap.model.cursor.SingletonCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.entry.ClonedServerEntry;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursorImpl;
import org.apache.directory.server.core.api.interceptor.context.*;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.partition.Subordinates;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.directory.server.core.api.filtering.*;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;

/**
 * Created by daniel on 6/29/16.
 */
public class GooglePartition implements Partition {

    private static final Logger log = LogManager.getLogger(GooglePartition.class);

    private String GOOGLE_DN = "";
    private String GOOGLE_GROUPS_DN = "ou=groups,";
    private String GOOGLE_USERS_DN = "ou=users,";
    private static final String MODIFICATION_NOT_ALLOWED_MSG = "This simple partition does not allow modification.";

    private SchemaManager schemaManager;

    private Dn googleDn;

    private Entry googleEntry;
    private Entry googleGroupsEntry;
    private Entry googleUsersEntry;

    private LRUCacheMap<String, Entry> entryCache;

    private List<Entry> googleOneLevelList;

    private AtomicBoolean initialized;

    private String id;

    private com.dabsquared.googleldap.DirectoryService service;

    private String domain = null;

    public GooglePartition(String domain)
    {
        initialized = new AtomicBoolean(false);
        entryCache = new LRUCacheMap<String, Entry>(300);
        this.domain = domain;

        String[] splits = this.domain.split("\\.");
        GOOGLE_DN = "dc=" + splits[0] + ",dc=" + splits[1];

        GOOGLE_GROUPS_DN = GOOGLE_GROUPS_DN + GOOGLE_DN;
        GOOGLE_USERS_DN = GOOGLE_USERS_DN + GOOGLE_DN;

        // Build a new authorized API client service.
        service = new com.dabsquared.googleldap.DirectoryService();
    }

    public String getId() {
        return id;
    }

    public void setId(String s) {
        this.id = s;
    }

    public SchemaManager getSchemaManager() {
        return schemaManager;
    }

    public void setSchemaManager(SchemaManager schemaManager) {
        this.schemaManager = schemaManager;
    }

    public void initialize() throws LdapException {
        if (!initialized.getAndSet(true)) {

            log.debug("==> GooglePartition::init");

            String infoMsg = String.format("Initializing %s with %s", this.getClass().getSimpleName(), GOOGLE_DN);
            log.info(infoMsg);

            // Create LDAP Dn
            googleDn = new Dn(schemaManager, GOOGLE_DN);

            Rdn rdn = googleDn.getRdn();
            googleEntry = new DefaultEntry(schemaManager, googleDn);
            googleEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.DOMAIN_OC, SchemaConstants.DC_OBJECT_OC);
            googleEntry.put(SchemaConstants.DC_AT, googleDn.getRdn(0).getValue());
            googleEntry.put("description", "Google Domain");


            Dn groupDn = new Dn(schemaManager, GOOGLE_GROUPS_DN);
            googleGroupsEntry = new DefaultEntry(schemaManager, groupDn);
            googleGroupsEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_UNIT_OC);
            googleGroupsEntry.put(SchemaConstants.OU_AT, "groups");
            googleGroupsEntry.put("description", "Google Groups");


            Dn  usersDn = new Dn(this.schemaManager, GOOGLE_USERS_DN);
            googleUsersEntry = new DefaultEntry(schemaManager, usersDn);
            googleUsersEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_UNIT_OC);
            googleUsersEntry.put(SchemaConstants.OU_AT, "users");
            googleUsersEntry.put("description", "Google Users");

            //Prepare list
            googleOneLevelList = new ArrayList<Entry>();
            googleOneLevelList.add(googleGroupsEntry);
            googleOneLevelList.add(googleUsersEntry);
            googleOneLevelList = Collections.unmodifiableList(googleOneLevelList);

            //Add to cache
            entryCache.put(googleDn.getName(), googleEntry);
            entryCache.put(groupDn.getName(), googleGroupsEntry);
            entryCache.put(usersDn.getName(), googleUsersEntry);

            log.debug("<== GooglePartition::init");
        }
    }

    public void repair() throws Exception {

    }

    public Dn getSuffixDn() {
        return googleDn;
    }

    public void setSuffixDn(Dn dn) throws LdapInvalidDnException {
        this.googleDn = dn;
        this.googleEntry.setDn(dn);
    }

    public void destroy() throws Exception {

    }

    public boolean isInitialized() {
        return initialized.get();
    }

    public void sync() throws Exception {

    }

    public Entry delete(DeleteOperationContext deleteOperationContext) throws LdapException {
        return null;
    }

    public void add(AddOperationContext addOperationContext) throws LdapException {
        throw new LdapException(MODIFICATION_NOT_ALLOWED_MSG);
    }

    public void modify(ModifyOperationContext modifyOperationContext) throws LdapException {
        throw new LdapException(MODIFICATION_NOT_ALLOWED_MSG);
    }

    public EntryFilteringCursor search(SearchOperationContext searchOperationContext) throws LdapException {
        /*
        -base: the node itself
        -one: one level under the node
        -sub: all node under the node
    */

        if (log.isDebugEnabled()) {
            log.debug("search((dn=" + searchOperationContext.getDn() + ", filter="
                    + searchOperationContext.getFilter() + ", scope=" + searchOperationContext.getScope() + ")");
        }

        switch (searchOperationContext.getScope()) {
            case OBJECT:
                return findObject(searchOperationContext);
            case ONELEVEL:
                return findOneLevel(searchOperationContext);
            case SUBTREE:
                return findSubTree(searchOperationContext);
            default:
                // return an empty result
                return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), searchOperationContext, this.schemaManager);
        }
    }

    public Entry lookup(LookupOperationContext lookupOperationContext) throws LdapException {
        Dn dn = lookupOperationContext.getDn();

        if (log.isDebugEnabled()) {
          log.debug("lookup(dn=" + lookupOperationContext.getDn() + ")");
        }

        Entry se = entryCache.get(lookupOperationContext.getDn().getName());
        if (se == null) {
            //todo
            log.debug("lookup()::No cached entry found for " + dn.getName());
            return null;
        } else {
            log.debug("lookup()::Cached entry found for " + dn.getName());
            return new ClonedServerEntry(se);
        }
    }

    public boolean hasEntry(HasEntryOperationContext hasEntryOperationContext) throws LdapException {
        Dn dn = hasEntryOperationContext.getDn();

        if (log.isDebugEnabled()) {
          log.debug("hasEntry(dn=" + hasEntryOperationContext.getDn() + ")");
        }

        if (entryCache.containsKey(hasEntryOperationContext.getDn().getName())) {
            return true;
        } else {
            int dnSize = dn.size();

            if (dnSize == 2) {
                if (isGoogle(dn)) {
                    entryCache.put(dn.getName(), googleEntry);
                    return true;
                } else {
                    return false;
                }
            } else if (dnSize == 3) {
                if (isGoogleGroups(dn)) {
                    entryCache.put(dn.getName(), googleGroupsEntry);
                    return true;
                } else if (isGoogleUsers(dn)) {
                    entryCache.put(dn.getName(), googleUsersEntry);
                    return true;
                } else {
                    return false;
                }
            } else if (dnSize == 4) {
                Dn prefix = dn.getParent();
                try {
                    prefix.apply(schemaManager);
                } catch (Exception ex) {
                    log.error("hasEntry()", ex);
                }
                log.debug("Prefix=" + prefix);
                if (isGoogleUsers(prefix)) {
                    Rdn rdn = dn.getRdn(2);
                    String user = rdn.getNormValue();
                    log.debug("user=" + user);
                    Entry userEntry = createUserEntry(dn, null);
                    return (userEntry != null);
                } else if(isGoogleGroups(prefix)) {
                    Rdn rdn = dn.getRdn(2);
                    String group = rdn.getNormValue();
                    log.debug("group=" + group);
                    Entry groupEntry = null;//TODO: createGroupEntry(dn);
                    return (groupEntry != null);
                } else {
                    log.debug("Prefix is neither users nor groups");
                    log.debug("Google Users = " + googleUsersEntry.getDn());
                    log.debug("Google Groups = " + googleGroupsEntry.getDn().toString());
                    return false;
                }
            }

        }
        return false;
    }

    public void rename(RenameOperationContext renameOperationContext) throws LdapException {
        throw new LdapException(MODIFICATION_NOT_ALLOWED_MSG);
    }

    public void move(MoveOperationContext moveOperationContext) throws LdapException {
        throw new LdapException(MODIFICATION_NOT_ALLOWED_MSG);
    }

    public void moveAndRename(MoveAndRenameOperationContext moveAndRenameOperationContext) throws LdapException {
        throw new LdapException(MODIFICATION_NOT_ALLOWED_MSG);
    }

    public void unbind(UnbindOperationContext unbindOperationContext) throws LdapException {
        log.debug("unbind()::opContext=" + unbindOperationContext.toString());
    }

    public void dumpIndex(OutputStream outputStream, String s) throws IOException {

    }

    public void setCacheService(CacheService cacheService) {

    }

    public String getContextCsn() {
        return null;
    }

    public void saveContextCsn() throws Exception {

    }

    public Subordinates getSubordinates(Entry entry) throws LdapException {
        return null;
    }


    private EntryFilteringCursor findObject(SearchOperationContext ctx) {
        Dn dn = ctx.getDn();
        Entry se = ctx.getEntry();

        //1. Try cache
        se = entryCache.get(dn.getName());
        if (se != null) {
            return new EntryFilteringCursorImpl(
                    new SingletonCursor<Entry>(se), ctx, this.schemaManager);
        }
        // return an empty result
        return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), ctx, this.schemaManager);
    }//findObject

    private EntryFilteringCursor findOneLevel(SearchOperationContext ctx) {
        Dn dn = ctx.getDn();
        Entry se = ctx.getEntry();

        if(se == null) {
            if(dn.equals(this.googleDn)) {
                return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), ctx, this.schemaManager);
            }
        }
        //log.debug("findOneLevel()::dn=" + dn.getName() + "::entry=" + se.toString() + "::filter=" + ctx.getFilter().toString());

        //1. Organizational Units
        if (dn.getName().equals(googleEntry.getDn().getName())) {
            return new EntryFilteringCursorImpl(
                    new ListCursor<Entry>(googleOneLevelList),
                    ctx,
                    this.schemaManager
            );
        }
        //2. Groups
        if (dn.equals(googleGroupsEntry.getDn())) {

            List<Entry> l = new ArrayList<Entry>();
            try {
                //TermRestriction<String> groupName = new TermRestriction<String>(GroupTermKeys.NAME, MatchMode.CONTAINS, "");
                //List<String> list = m_CrowdClient.searchGroupNames(groupName, 0, Integer.MAX_VALUE);
                //for (String gn : list) {
                  //  Dn gdn = new Dn(this.schemaManager, String.format("uid=%s,%s", gn, GOOGLE_GROUPS_DN));
                    //TODO: l.add(createGroupEntry(gdn));
                //}
            } catch (Exception ex) {
                log.error("findOneLevel()", ex);
            }
            return new EntryFilteringCursorImpl(
                    new ListCursor<Entry>(l),
                    ctx,
                    this.schemaManager
            );
        }

        //3. Users
        if (dn.equals(googleUsersEntry.getDn())) {
            List<Entry> l = new ArrayList<Entry>();
            try {
                List<User> users = this.service.getDirectoryService().users().list().setCustomer("my_customer").execute().getUsers();
                for (User un : users) {
                    String email = un.getPrimaryEmail();
                    String[] tokens = email.split("@");

                    Dn udn = new Dn(this.schemaManager, String.format("cn=%s,%s", tokens[0], GOOGLE_USERS_DN));
                    l.add(createUserEntry(udn, un));
                }
            } catch (Exception ex) {
                log.error("findOneLevel()", ex);
            }
            return new EntryFilteringCursorImpl(
                    new ListCursor<Entry>(l),
                    ctx,
                    this.schemaManager
            );
        }

        // return an empty result
        return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), ctx, this.schemaManager);
    }

    private EntryFilteringCursor findSubTree(SearchOperationContext ctx) {
        Dn dn = ctx.getDn();

        log.debug("findSubTree()::dn=" + dn.getName());
        //Will only search at one level
        return findOneLevel(ctx);
    }



    private Entry createUserEntry(Dn dn, User user) {
        Entry userEntry = entryCache.get(dn.getName());
        try {
            dn.apply(this.schemaManager);
        } catch (LdapInvalidDnException e) {
            e.printStackTrace();
        }
        if (userEntry == null) {
            try {
                //1. Obtain from Google
                Rdn rdn = dn.getRdn(0);
                String username = rdn.getNormValue();

                String userToCheck = username;
                if (domain != null) {
                    userToCheck = username + "@" + this.domain;
                }

                if (user == null) {
                    user = service.getDirectoryService().users().get(userToCheck).execute();
                }

                //2. Create entry
                userEntry = new DefaultEntry(schemaManager, dn);
                userEntry.put("objectClass", SchemaConstants.INET_ORG_PERSON_OC);
                userEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_PERSON_OC, SchemaConstants.PERSON_OC, SchemaConstants.INET_ORG_PERSON_OC, "posixAccount");
                userEntry.put(SchemaConstants.CN_AT, username);
                userEntry.put(SchemaConstants.CN_AT, user.getName().getFullName());
                userEntry.put(SchemaConstants.UID_AT, username);
                userEntry.put(SchemaConstants.EMAIL_AT, user.getPrimaryEmail());
                userEntry.put(SchemaConstants.GIVENNAME_AT, user.getName().getGivenName());
                userEntry.put(SchemaConstants.SN_AT, user.getName().getFamilyName());
                userEntry.put(SchemaConstants.OU_AT, "users");
                userEntry.put(SchemaConstants.UID_NUMBER_AT, user.getId());

                List <ArrayMap> phones = (List<ArrayMap>) user.getPhones();
                if (phones != null) {
                    for (ArrayMap phone: phones) {
                        if (phone.get("type").equals("mobile")) {
                            userEntry.put(SchemaConstants.MOBILE_TELEPHONE_NUMBER_AT, phone.get("value").toString());
                        } else if (phone.get("type").equals("work")) {
                            userEntry.put(SchemaConstants.TELEPHONE_NUMBER_AT, phone.get("value").toString());
                        }
                    }
                }


                List <ArrayMap> emails = (List<ArrayMap>) user.getEmails();
                if (emails != null) {
                    for (ArrayMap email: emails) {
                        userEntry.add(SchemaConstants.EMAIL_AT, email.get("address").toString());
                    }
                }

                // Print the first 10 users in the domain.
                List<ArrayMap> aliases = null;
                try {
                    aliases = (List<ArrayMap>)(Object) service.getDirectoryService().users().aliases().list(user.getPrimaryEmail()).execute().getAliases();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                if (aliases != null) {
                    for (ArrayMap alias : aliases) {
                        userEntry.add(SchemaConstants.EMAIL_AT, alias.get("alias").toString());
                    }
                }



                entryCache.put(dn.getName(), userEntry);
            } catch (Exception ex) {
                log.debug("createUserEntry()", ex);
            }
        }
        return userEntry;
    }

    private boolean isGoogle(Dn dn) {
        return googleEntry.getDn().equals(dn);
    }

    private boolean isGoogleGroups(Dn dn) {
        return googleGroupsEntry.getDn().equals(dn);
    }

    private boolean isGoogleUsers(Dn dn) {
        return googleUsersEntry.getDn().equals(dn);
    }


}

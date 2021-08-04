#from ldap3 import Server, Connection, ALL, NTLM, Tls
import ldap, ldap.modlist
from usermanagement.user import User
from usermanagement.group import Group
class LDAPConn:
    def __init__(self, server, user = None, passwd = None):
        self.server = server
        self.ldap = server._get_conn()
        if user:
            self.user = User(self, user, passwd)
        else:
            self.user = None

    def __enter__(self):
        if self.usser:
            self.user.authenticate()
        return self

    def __exit__(self, type, calue, traceback):
        if not self.conn is None:
            self.conn.unbind()

    def find_domain(self):
        target_info = self.ldap.search_s(self.server.base_domain_dn_str, ldap.SCOPE_SUBTREE, '(sambaDomainName=*)', attrlist=['dn', 'sambaDomainName','sambaSID'])
        if len(target_info) > 1:
            RuntimeError('too many domains found')
        if len(target_info) == 0:
            RuntimeError('no domains found')
        return target_info[0]

    def next_uid(self, domain, uid_type='uidNumber'):
        if not uid_type in ['sambaNextRid','gidNumber','uidNumber']:
            raise RuntimeError('Unknown UID type: %s' % uid)
        uid = self.ldap.search_s(domain, ldap.SCOPE_SUBTREE, attrlist=[uid_type])
        if len(uid) != 1:
            RuntimeError('To many/few RID\'s found')
        uid = uid[0]
        mod_old = uid[1]
        uid = int(mod_old[uid_type][0].decode('utf8'))
        modlist = ldap.modlist.modifyModlist(mod_old,{uid_type:[str(uid+1).encode('utf8')]})
        ret = self.ldap.modify_s(domain,modlist)
        if uid_type == 'sambaNextRid':
            #sambaNextRid stores the last id used rather than the next to be used... Thanks for the consistency guys...
            return uid+1
        else:
           return uid

    def next_rid(self,domain):
        return self.next_uid(domain,'sambaNextRid')

    def next_gid(self,domain):
        return self.next_uid(domain,'gidNumber')

    def User(self, uid, passwd = None):
        return User(self, uid, passwd)

    def Group(self, **kwargs):
        return Group(self, **kwargs)


class LDAPServer:
    #def __init__(self, host, port=636, validate_tls=True):
    #    tls = ldap3.Tls(validate=validate_tls)
    #    self.server = ldap3.Server('cheka.mithri.date', port=port, get_info=ldap3.ALL, use_ssl=True,tls=tls)

    def __init__(self, url, base, user_base = None, group_base = None, guest_group = 'Domain Guests', user_group = 'Domain Users'):
        self.url = url
        self.base_domain_dn_str = base

        if user_base is None:
            self.user_dn_str = 'ou=People, %s' % self.base_domain_dn_str
        else:
            self.user_dn_str = user_base
        self.user_dn = ldap.dn.str2dn(self.user_dn_str)

        if group_base is None:
            self.group_dn_str = 'ou=Groups, %s' % self.base_domain_dn_str
        else:
            self.group_dn_str = user_base
        self.group_dn = ldap.dn.str2dn(self.group_dn_str)

        self.user_group = user_group
        self.guest_group = guest_group

    def _uid_to_dn(cls, uid):
        return ldap.dn.dn2str([[('uid', uid, 1)]]+cls.user_dn)

    def _cn_to_group_dn(cls, cn):
        return ldap.dn.dn2str([[('cn', cn, 1)]]+cls.group_dn)

    def _get_conn(self):
        return ldap.initialize(self.url)

    def connect(self,user = None,passwd = None):
        return LDAPConn(self,user,passwd)

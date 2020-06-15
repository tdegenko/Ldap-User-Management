#from ldap3 import Server, Connection, ALL, NTLM, Tls
import ldap, ldap.modlist
import hashlib, binascii
import hmac

class LDAPUtils:
    @classmethod
    def ntlmv1(cls,pw):
        return binascii.hexlify(hashlib.new('md4', pw.encode('utf-16le')).digest())

    @classmethod
    def ntlmv2(cls,pw,user=None,domain=None):
        v1Hash = cls._ntlmv1(pw)
        data = (user.upper() + domain.upper()).encode('utf-16le')
        return binascii.hexlify(hmac.new(v1Hash, data).digest())


class LDAPConn:
    def __init__(self, server, user, passwd):
        self.server = server
        self.conn = server._get_conn()
        self.user = self.find_user(user)
        self._passwd = passwd

    def __enter__(self):
        self.authenticate_user()
        return self

    def __exit__(self, type, calue, traceback):
        if not self.conn is None:
            self.conn.unbind()

    def find_user(self, target):
        target_info = self.conn.search_s(self.server.user_dn_str,ldap.SCOPE_SUBTREE,ldap.dn.dn2str([[('uid',target,1)]]),attrlist=['dn'])
        if len(target_info) == 1:
            return target_info[0][0]
        elif len(target_info) == 0:
            return None
        else:
            raise RuntimeError('Too many users found')

    def find_domain(self):
        target_info = self.conn.search_s(self.server.base_domain_dn_str, ldap.SCOPE_SUBTREE, '(sambaDomainName=*)', attrlist=['dn', 'sambaDomainName','sambaSID'])
        if len(target_info) > 1:
            RuntimeError('too many domains found')
        if len(target_info) == 0:
            RuntimeError('no domains found')
        return target_info[0]

    def next_uid(self, domain, uid_type='uidNumber'):
        if not uid_type in ['sambaNextRid','gidNumber','uidNumber']:
            raise RuntimeError('Unknown UID type: %s' % uid)
        uid = self.conn.search_s(domain, ldap.SCOPE_SUBTREE, attrlist=[uid_type])
        if len(uid) != 1:
            RuntimeError('To many/few RID\'s found')
        uid = uid[0]
        mod_old = uid[1]
        uid = int(mod_old[uid_type][0].decode('utf8'))
        modlist = ldap.modlist.modifyModlist(mod_old,{uid_type:[str(uid+1).encode('utf8')]})
        ret = self.conn.modify_s(domain,modlist)
        if uid_type == 'sambaNextRid':
            #sambaNextRid stores the last id used rather than the next to be used... Thanks for the consistency guys...
            return uid+1
        else:
           return uid

    def find_gid(self, group):
        target_info = self.conn.search_s(self.server.group_dn_str,ldap.SCOPE_SUBTREE,ldap.dn.dn2str([[('cn',group,1)]]),attrlist=['gidNumber'])
        if len(target_info) == 1:
            return target_info[0][1]['gidNumber'][0]
        elif len(target_info) == 0:
            return None
        else:
            raise RuntimeError('Too many groups found')

    def find_guest_gid(self):
        return self.find_gid(self.server.guest_group)

    def find_domain_user_gid(self):
        return self.find_gid(self.server.user_group)

    def next_rid(self,domain):
        return self.next_uid(domain,'sambaNextRid')

    def next_gid(self,domain):
        return self.next_uid(domain,'gidNumber')



    def authenticate_user(self):
        try:
            self.conn.simple_bind_s(self.user, self._passwd)
            return True
        except ldap.INVALID_CREDENTIALS:
            return False

    def update_password(self, new_pw):
        new_ntlm = LDAPUtils.ntlmv1(new_pw)
        ntlm_mod = ldap.modlist.modifyModlist({'sambaNTPassword':['*']},{'sambaNTPassword':[new_ntlm]})
        self.conn.modify_s(self.user,ntlm_mod)
        self.conn.passwd_s(self.user, self._passwd, new_pw)
        self._passwd = new_pw
        self.authenticate_user()

    def group_from_gid(self, gid):
        target_info = self.conn.search_s(self.server.group_dn_str, ldap.SCOPE_SUBTREE,ldap.dn.dn2str([[('gidNumber',gid,1)]]),attrlist=['dn','description','gidNumber'])

        if len(target_info) > 1:
            RuntimeError('Too many groups found')
        if len(target_info) == 0:
            RuntimeError('No groups found')

        result = {
            'dn': target_info[0][0],
            'gid': gid,
            'description': target_info[0][1]['description'][0].decode()
        }
        return result

    def group_info(self, group):
        target_info = self.conn.search_s(group,ldap.SCOPE_BASE,attrlist=['dn','description','gidNumber'])
        if len(target_info) > 1:
            RuntimeError('Too many groups found')
        if len(target_info) == 0:
            RuntimeError('No groups found')
        target_info = target_info[0]

        result = {
            'dn': target_info[0],
            'gid': target_info[1]['gidNumber'][0].decode(),
            'description': target_info[1]['description'][0].decode()
        }
        return result

    def get_groups(self, user = None):
        if user is None:
            user = self.user
        else:
            user = self.find_user(user)
        target_info = self.conn.search_s(user,ldap.SCOPE_BASE,attrlist=['memberOf','gidNumber'])

        if len(target_info) > 1:
            RuntimeError('Too many users results found')
        if len(target_info) == 0:
            RuntimeError('No groups found')
        target_info = target_info[0][1]


        results = {
            'primary': self.group_from_gid(target_info['gidNumber'][0].decode()),
            'secondary': [self.group_info(x.decode()) for x in target_info.get('memberOf',[])],
        }

        return results

    def user_add_group (self, user, group):
        target_dn =  self.server._cn_to_group_dn(group)
        user_dn = self.find_user(user)
        group_mod = [(ldap.MOD_ADD, 'memberUid', [user.encode()]),(ldap.MOD_ADD, 'member', [user_dn.encode()])]
        self.conn.modify_s(target_dn, group_mod)


    def add_user(self, new_user, name, new_pw, primary_group = None,additional_groups = []):
        if primary_group is None:
            primary_group = self.server.user_group
        user_dn = self.server._uid_to_dn(new_user)
        domain, domain_info = self.find_domain()
        sid = '%s-%d' % (domain_info['sambaSID'][0].decode('utf8'),self.next_rid(domain))
        user = {
            'uid': new_user.encode(),
            'uidNumber': str(self.next_uid(domain)).encode('utf8'),
            'gidNumber': self.find_gid(primary_group),
            'cn': name[0].encode(),
            'sn': name[1].encode(),
            'objectClass': [
                b'top',
                b'person',
                #b'organizationalPerson',
                b'posixAccount',
                b'shadowAccount',
                #b'inetOrgPerson',
                b'sambaSamAccount',
                b'radiusprofile',
            ],
            'loginShell': b'/bin/bash',
            'homeDirectory': ('/home/%s' % new_user).encode(),
            'radiusTunnelType': b'VLAN',
            'radiusTunnelMediumType': b'IEEE-802',
            'radiusTunnelPrivateGroupId': b'100',
            'sambaSID': sid.encode('utf8'),
            'sambaNTPassword':[b'XXX'],
        }
        user_add = ldap.modlist.addModlist(user)
        self.conn.add_s(user_dn,user_add)
        self.user_add_group(new_user, primary_group)
        for group in additional_groups:
            self.user_add_group(new_user, group)
        self.reset_password(new_user, new_pw)

    def add_guest(self, guest, guest_name, guest_pw):
        self.add_user(guest, guest_name, guest_pw, primary_group = self.server.guest_group)

    def reset_password(self,target, target_pw):
        target_dn = self.find_user(target)
        ntlm = LDAPUtils.ntlmv1(target_pw)
        ntlm_mod = ldap.modlist.modifyModlist({'sambaNTPassword':['*']},{'sambaNTPassword':[ntlm]})
        self.conn.modify_s(target_dn, ntlm_mod)
        self.conn.passwd_s(target_dn, None, target_pw)



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
        self.guest_group = user_group

    def _uid_to_dn(cls, uid):
        return ldap.dn.dn2str([[('uid', uid, 1)]]+cls.user_dn)

    def _cn_to_group_dn(cls, cn):
        return ldap.dn.dn2str([[('cn', cn, 1)]]+cls.group_dn)

    def _get_conn(self):
        return ldap.initialize(self.url)

    def connect(self,user,passwd):
        return LDAPConn(self,user,passwd)

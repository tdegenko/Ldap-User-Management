import usermanagement.utils as utils
from usermanagement.group import Group
import ldap, ldap.modlist

class User:

    def __init__(self, connection, uid, passwd = None):
        self.conn = connection
        self.uid = uid
        self.user_dn = self._find_user(uid)
        self._passwd = passwd
        self.authenticated = False

    @classmethod
    def add(cls, conn, new_user, name, new_pw, primary_group = None, additional_groups = []):
        if primary_group is None:
            primary_group = Group.Users(conn)
        user_dn = conn.server._uid_to_dn(new_user)
        domain, domain_info = conn.find_domain()
        sid = '%s-%d' % (domain_info['sambaSID'][0].decode('utf8'), conn.next_rid(domain))
        user = {
            'uid': new_user.encode(),
            'uidNumber': str(conn.next_uid(domain)).encode('utf8'),
            'gidNumber': primary_group.gid.encode(),
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
        conn.ldap.add_s(user_dn,user_add)
        user = cls(conn, new_user)
        user.add_group(primary_group)
        for group in additional_groups:
            user.add_group(group)
        user.update_password(new_pw)
        return user

    @classmethod
    def add_guest(cls, conn, guest, guest_name, guest_pw):
        cls.add(conn, guest, guest_name, guest_pw, primary_group = Group.Guests(conn))

    def _find_user(self, target):
        target_info = self.conn.ldap.search_s(self.conn.server.user_dn_str,ldap.SCOPE_SUBTREE,ldap.dn.dn2str([[('uid',target,1)]]),attrlist=['dn'])
        if len(target_info) == 1:
            return target_info[0][0]
        elif len(target_info) == 0:
            return None
        else:
            raise RuntimeError('Too many users found')

    def authenticate(self, passwd = None):
        if passwd is None:
            passwd = self._passwd
        try:
            self.conn.ldap.simple_bind_s(self.user_dn, self._passwd)
            self.authenticateed = True
            return True
        except ldap.INVALID_CREDENTIALS:
            return False

    def update_password(self, new_pw):
        new_ntlm = utils.LDAPUtils.ntlmv1(new_pw)
        ntlm_mod = ldap.modlist.modifyModlist({'sambaNTPassword':['*']},{'sambaNTPassword':[new_ntlm]})
        self.conn.ldap.modify_s(self.user_dn, ntlm_mod)
        self.conn.ldap.passwd_s(self.user_dn, self._passwd, new_pw)
        if self._passwd is not None:
            self._passwd = new_pw
        elif self.authenticated:
            self.authenticate()

    def get_groups(self):
        target_info = self.conn.ldap.search_s(self.user_dn,ldap.SCOPE_BASE,attrlist=['memberOf','gidNumber'])

        if len(target_info) > 1:
            RuntimeError('Too many users results found')
        if len(target_info) == 0:
            RuntimeError('No groups found')
        target_info = target_info[0][1]


        results = {
            'primary': Group(connection = self.conn, gid = target_info['gidNumber'][0].decode()),
            'secondary': [Group(connection = self.conn, dn = x.decode()) for x in target_info.get('memberOf',[])],
        }

        return results

    def add_group(self, group):
        group.add_user(self)

    def remove_group(self, group):
        group.remove_user(self)

    def change_primary_group(self, group):
        raise NotImplementedError()

    def delete(self):
        groups = self.get_groups()
        for group in groups['secondary']:
            group.remove_user(self)
        self.conn.ldap.delete_s(self.user_dn)

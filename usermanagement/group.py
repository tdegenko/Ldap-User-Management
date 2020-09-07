import ldap, ldap.modlist
class Group:
    @classmethod
    def Guests(cls, connection):
        return cls(connection, name = connection.server.guest_group)

    @classmethod
    def Users(cls, connection):
        return cls(connection, name = connection.server.user_group)

    keys = ['dn','description','gidNumber']

    def __init__(self, connection, name = None, gid = None, dn = None):
        self.conn = connection
        group = self._group_info(description = name, gid = gid, dn = dn)
        print(group)
        self.gid = group['gid']
        self.description = group['description']
        self.dn = group['dn']

    def _group_info(self, description = None, gid = None, dn = None):
        target_info = []
        if gid is not None:
            target_info = self.conn.ldap.search_s(self.conn.server.group_dn_str, ldap.SCOPE_SUBTREE,ldap.dn.dn2str([[('gidNumber',gid,1)]]),attrlist=self.keys)
        elif dn is not None:
            target_info = self.conn.ldap.search_s(dn,ldap.SCOPE_BASE,attrlist=self.keys)
        elif description is not None:
            target_info = self.conn.ldap.search_s(self.conn.server.group_dn_str,ldap.SCOPE_SUBTREE,ldap.dn.dn2str([[('cn',description,1)]]),attrlist=self.keys)
        else:
            raise RuntimeError('Must provide either group name, dn, or gidNumber')

        if len(target_info) > 1:
            RuntimeError('Too many groups found')
        if len(target_info) == 0:
            RuntimeError('No groups found')

        result = {
            'dn': target_info[0][0],
            'gid': target_info[0][1]['gidNumber'][0].decode(),
            'description': target_info[0][1]['description'][0].decode()
        }
        return result

    def add_user(self, user):
        group = {
            'memberUid': [user.uid.encode()],
            'member': [user.user_dn.encode()],
        }
        group_mod = ldap.modlist.modifyModlist({}, group)
        self.conn.ldap.modify_s(self.dn, group_mod)

    def remove_user(self, user):
        group = {
            'memberUid': [user.uid.encode()],
            'member': [user.user_dn.encode()],
        }
        group_mod = ldap.modlist.modifyModlist(group, {})
        self.conn.ldap.modify_s(self.dn, group_mod)

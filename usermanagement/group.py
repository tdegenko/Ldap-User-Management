import ldap, ldap.modlist


class Group:
    @classmethod
    def Groups(cls, connection):
        groups = connection.ldap.search_s(
            connection.server.group_dn_str,
            ldap.SCOPE_SUBTREE,
            "(gidNumber=*)",
            attrlist=cls.keys,
        )
        return [cls(connection, dn=x) for x, _ in groups]

    @classmethod
    def Guests(cls, connection):
        return cls(connection, name=connection.server.guest_group)

    @classmethod
    def Users(cls, connection):
        return cls(connection, name=connection.server.user_group)

    @classmethod
    def Computers(cls, connection):
        return cls(connection, name=connection.server.computer_group)

    keys = ["dn", "cn", "gidNumber"]

    def __init__(self, connection, name=None, gid=None, dn=None):
        self.conn = connection
        group = self._group_info(cn=name, gid=gid, dn=dn)
        self.gid = group["gid"]
        self.cn = group["cn"]
        self.dn = group["dn"]

    def __eq__(self, other):
        if not isinstance(other, Group):
            return False
        return (
            self.conn.server == other.conn.server
            and self.gid == other.gid
            and self.cn == other.cn
            and self.dn == other.dn
        )

    def _group_info(self, cn=None, gid=None, dn=None):
        target_info = []
        if gid is not None:
            target_info = self.conn.ldap.search_s(
                self.conn.server.group_dn_str,
                ldap.SCOPE_SUBTREE,
                ldap.dn.dn2str([[("gidNumber", gid, 1)]]),
                attrlist=self.keys,
            )
        elif dn is not None:
            target_info = self.conn.ldap.search_s(
                dn, ldap.SCOPE_BASE, attrlist=self.keys
            )
        elif cn is not None:
            target_info = self.conn.ldap.search_s(
                self.conn.server.group_dn_str,
                ldap.SCOPE_SUBTREE,
                ldap.dn.dn2str([[("cn", cn, 1)]]),
                attrlist=self.keys,
            )
        else:
            raise RuntimeError("Must provide either group name, dn, or gidNumber")

        if len(target_info) > 1:
            raise RuntimeError("Too many groups found")
        if len(target_info) == 0:
            raise RuntimeError("No groups found")

        result = {
            "dn": target_info[0][0],
            "gid": target_info[0][1]["gidNumber"][0].decode(),
            "cn": target_info[0][1]["cn"][0].decode(),
        }
        return result

    def get_users(self):
        target_info = self.conn.ldap.search_s(
            self.conn.server.user_dn_str,
            ldap.SCOPE_SUBTREE,
            "(|(gidNumber=%(gid)s)(memberOf=%(dn)s))" % self.__dict__,
            attrlist=["uid"],
        )

        return [self.conn.User(u[1]["uid"][0].decode()) for u in target_info]

    def add_user(self, user):
        group = {
            "memberUid": [user.uid.encode()],
            "member": [user.user_dn.encode()],
        }
        group_mod = ldap.modlist.modifyModlist({}, group)
        self.conn.ldap.modify_s(self.dn, group_mod)

    def remove_user(self, user):
        users = self.get_users()
        new_users = [u for u in users if u.uid != user.uid]
        group = {
            "memberUid": [u.uid.encode() for u in users],
            "member": [u.user_dn.encode() for u in users],
        }
        group_new = {
            "memberUid": [u.uid.encode() for u in new_users],
            "member": [u.user_dn.encode() for u in new_users],
        }
        group_mod = ldap.modlist.modifyModlist(group, group_new)
        self.conn.ldap.modify_s(self.dn, group_mod)

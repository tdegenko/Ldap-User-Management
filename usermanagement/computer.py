from usermanagement.group import Group
import ldap, ldap.modlist


class Computer:
    def __init__(self, connection, uid):
        self.conn = connection
        self.uid = uid
        self.computer_dn = self._find_computer(uid)

    @classmethod
    def add(cls, conn, name, new_pw):
        primary_group = Group.Computers(conn)
        computer_dn = conn.server._uid_to_computer_dn(name)
        domain, domain_info = conn.find_domain()
        sid = "%s-%d" % (
            domain_info["sambaSID"][0].decode("utf8"),
            conn.next_rid(domain),
        )
        computer = {
            "uid": name.encode(),
            "cn": name.encode(),
            "uidNumber": str(conn.next_uid(domain)).encode("utf8"),
            "gidNumber": primary_group.gid.encode(),
            "objectClass": [
                b"top",
                b"device",
                b"posixAccount",
                b"shadowAccount",
            ],
            "loginShell": b"/bin/false",
            "homeDirectory": b"/nonexistent",
            "description": b"Computer",
            "gecos": b"Computer",
        }
        computer_add = ldap.modlist.addModlist(computer)
        conn.ldap.add_s(computer_dn, computer_add)
        computer = cls(conn, name)
        computer.update_password(new_pw)
        return computer

    @classmethod
    def all(cls, conn):
        computers = conn.ldap.search_s(
            conn.server.computer_dn_str, ldap.SCOPE_SUBTREE, "(uid=*)", attrlist=["uid"]
        )
        return [cls(conn, x[1]["uid"][0].decode()) for x in computers]

    def _find_computer(self, target):
        target_info = self.conn.ldap.search_s(
            self.conn.server.computer_dn_str,
            ldap.SCOPE_SUBTREE,
            ldap.dn.dn2str([[("uid", target, 1)]]),
            attrlist=["dn"],
        )
        if len(target_info) == 1:
            return target_info[0][0]
        elif len(target_info) == 0:
            return None
        else:
            raise RuntimeError("Too many computers found")

    def update_password(self, new_pw):
        self.conn.ldap.passwd_s(self.computer_dn, None, new_pw)

    def delete(self):
        self.conn.ldap.delete_s(self.computer_dn)

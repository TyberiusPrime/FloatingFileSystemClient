#!/usr/bin/python3
import collections
import re
import argparse
import pprint
import shlex
import subprocess
import os
import sys
import json
from signal import signal, SIGPIPE, SIG_DFL
from pathlib import Path
import gzip

# don't fail with BrokenPipeError in | head and such
signal(SIGPIPE, SIG_DFL)

FFS_CONFIG = {
    # you need host, port, and key,
    # optinoal certificate_dir (default: /home/ffs/certificates)
}


def load_config():
    try:
        c = json.loads(Path("/etc/ffs/client.json").read_text())
    except OSError:
        c = {}
    FFS_CONFIG.update(c)


if os.path.exists("/home/ffs"):
    keys_dir = "/home/ffs/certificates"
else:
    keys_dir = os.path.join(os.path.dirname(__file__), "certificates")
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)


def create_keys(keys_dir):
    import zmq
    import zmq.auth

    if not os.path.exists(os.path.join(keys_dir, "node.key_secret")):
        print("Creating keys, needs sudo")
        if not os.path.exists(keys_dir):
            subprocess.check_call(["sudo", "mkdir", keys_dir])
        subprocess.check_call(["sudo", "chmod", "0777", keys_dir])
        zmq.auth.create_certificates(keys_dir, "node")
        # only write removed - other users need to be able to
        # talk to the ffs_central as well.
        if keys_dir.startswith("/home/ffs"):
            subprocess.check_call(["sudo", "chown", "ffs", keys_dir, "-R"])
        subprocess.check_call(["sudo", "chmod", "0444", keys_dir, "-R"])
        subprocess.check_call(["sudo", "chmod", "0555", keys_dir])


def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, "Yi", suffix)


def to_bytes(s):
    number = float(re.findall("^[0-9.]+", s)[0])
    if s.endswith("T"):
        number *= 1024 ** 4
    elif s.endswith("G"):
        number *= 1024 ** 3
    elif s.endswith("M"):
        number *= 1024 ** 2
    elif s.endswith("k"):
        number *= 1024 ** 1
    else:
        pass
    return number


class FFS_Installer:
    def __init__(self, ffs_client):
        self.client = ffs_client

    def install(self, keys_dir):
        print("Installing FFS-Node on local machine")
        self.check_ffs_user_exists()
        self.check_ffs_home_rights()
        public_ssh_key = self.create_ssh_keys()
        self.inform_sudoers()
        self.install_packages()
        create_keys(keys_dir)
        self.download_node_code()
        ffs_storage_prefixes = self.check_ffs_zfs_present()
        print("")
        print("Here is the information for config.py:nodes on central")
        import socket

        hostname = socket.gethostname()
        for ffs_prefix in ffs_storage_prefixes:
            print(
                """'%(hostname)s': {
                'hostname': '%(hostname)s',
                'storage_prefix': '%(ffs_prefix)s',
                'public_key': %(public_key)s,
            },
            """
                % {
                    "hostname": hostname,
                    "ffs_prefix": ffs_prefix,
                    "public_key": repr(public_ssh_key),
                }
            )
        print("")
        print(
            "After altering config.py, central will restart and this node will be available."
        )

    def check_ffs_zfs_present(self):
        zfs_output = subprocess.check_output(
            ["sudo", "zfs", "get", "ffs:root", "-t", "filesystem", "-H"]
        ).decode("utf-8")
        zfs_list = zfs_output.strip().split("\n")
        zfs_list = [x.split("\t") for x in zfs_list]
        result = []
        for zfs, prop, value, source in zfs_list:
            if value == "on" and source == "local":
                result.append("/" + zfs)
        if not result:
            raise ValueError(
                "Please create ffs-zfs root by setting ffs:root=on on any zfs (sudo zfs set ffs:root=on pool/ffs"
            )
        return result

    def download_node_code(self):
        res = self.client.call_central({"msg": "deploy"})
        if "error" in res:
            print("Deploy received error result:")
            pprint.pprint(res)
            sys.exit(2)
        import io
        import zipfile
        import base64

        buffer = io.BytesIO(base64.b64decode(res["node.zip"]))
        zf = zipfile.ZipFile(buffer)
        # subprocess.check_call(['sudo', 'rm', '/home/ffs', '-r'])
        # subprocess.check_call(['sudo', 'mkdir', '/home/ffs/'])
        subprocess.check_call(["sudo", "chmod", "ugo+rwX", "/home/ffs"])
        subprocess.check_call(["sudo", "chmod", "ugo+rwX", "/home/ffs", "-R"])
        subprocess.check_call(["sudo", "chmod", "ugo+rwX", "/home/ffs/.ssh", "-R"])
        zf.extractall("/home/ffs/")
        Path("/home/ffs/node.log").touch()
        subprocess.check_call(["sudo", "chown", "ffs", "/home/ffs", "-R"])
        subprocess.check_call(["sudo", "chmod", "u-w,g-w,o-w", "/home/ffs"])
        subprocess.check_call(["sudo", "chmod", "u-w,g-w,o-w", "/home/ffs", "-R"])
        subprocess.check_call(["sudo", "chmod", "0700", "/home/ffs/.ssh"])
        subprocess.check_call(
            ["sudo", "chmod", "0644", "/home/ffs/.ssh/authorized_keys"]
        )
        subprocess.check_call(["sudo", "chmod", "0644", "/home/ffs/node.log"])

        subprocess.check_call(["sudo", "chmod", "0600", "/home/ffs/.ssh/id_rsa"])

        print("Downloaded current node code to /home/ffs")

    def install_packages(self):
        try:
            import zmq
        except ImportError:
            print("pip3 install pyzmq")
            subprocess.check_call(["sudo", "-E", "pip3", "install", "pyzmq"])

    def check_ffs_user_exists(self):
        import pwd

        users = pwd.getpwall()
        for u in users:
            if u.pw_name == "ffs":
                print("ffs user was present")
                break
        else:
            print("You need to create an ffs user first")
            print("Call:")
            print(" ".join(["sudo", "useradd", "-d", "/home/ffs", "-m", "ffs"]))
            print(" ".join(["sudo", "usermod", "-p", "nologin", "ffs"]))
            sys.exit(1)

    def check_ffs_home_rights(self):
        import stat

        to_check = [
            ("/home/ffs", "rwxr-xr-x"),
            ("/home/ffs/.ssh", "rwx------"),
            ("/home/ffs/.ssh/authorized_keys", "rw-r--r--"),
        ]
        for fn, supposed in to_check:
            actual = robust_rights(fn)[0]  # os.stat(fn)[stat.ST_MODE] & 0o777
            if actual != supposed:
                raise ValueError(
                    "%s had the wrong rights - must be %s for ssh login - was %s"
                    % (fn, supposed, actual)
                )

    def create_ssh_keys(self):
        if not os.path.exists("/home/ffs/.ssh"):
            subprocess.check_call(["sudo", "mkdir", "/home/ffs/.ssh"])
            subprocess.check_call(["sudo", "chown", "ffs", "/home/ffs/.ssh"])
            subprocess.check_call(["sudo", "chmod", "0700", "/home/ffs/.ssh"])
        try:
            subprocess.check_call(["sudo", "ls", "/home/ffs/.ssh/id_rsa"])
        except subprocess.CalledProcessError:
            print("Having to create keys")
            subprocess.check_call(
                " ".join(
                    [
                        "sudo",
                        "-u",
                        "ffs",
                        "ssh-keygen",
                        "-f",
                        "/home/ffs/.ssh/id_rsa",
                        "-t",
                        "rsa",
                        "-N",
                        "''",
                        "-q",
                    ]
                ),
                shell=True,
            )
        return subprocess.check_output(
            ["sudo", "cat", "/home/ffs/.ssh/id_rsa.pub"]
        ).strip()

    def inform_sudoers(self):
        stanca = b"""ffs ALL = (root) NOPASSWD: /sbin/zfs
	ffs ALL = (root) NOPASSWD: /sbin/zpool status
	ffs ALL = (root) NOPASSWD: /sbin/zpool status -P -L
	ffs ALL = (root) NOPASSWD: /sbin/mount.zfs
	ffs ALL = (root) NOPASSWD: /usr/sbin/zfs
	ffs ALL = (root) NOPASSWD: /usr/sbin/zpool status
	ffs ALL = (root) NOPASSWD: /usr/sbin/zpool status -P -L
	ffs ALL = (root) NOPASSWD: /usr/sbin/mount.zfs

	ffs ALL = (root) NOPASSWD: /bin/chmod
	ffs ALL = (root) NOPASSWD: /bin/chown
	ffs ALL = (root) NOPASSWD: /bin/mkdir
	ffs ALL = (root) NOPASSWD: /usr/bin/rsync
	ffs ALL = (root) NOPASSWD: /bin/umount"""
        files = [Path("/etc/sudoers")] + list(Path("/etc/sudoers.d").glob("*"))
        for f in files:
            existing_sudoers = subprocess.check_output(
                ["sudo", "cat", str(f.absolute())]
            )
            if stanca in existing_sudoers:
                return
        else:
            print("The ffs stance in /etc/sudoers is missing (or incomplete)")
            print(
                "Add the following to /etc/sudoers (not automatic due to the danger of lockout)"
            )
            print("")
            print(stanca.decode("utf-8"))
            sys.exit(1)


class FFSClient:
    def __init__(self, host, port, server_key, keys_dir, timeout=3000):
        self.host = host
        self.port = port
        self.server_key = server_key
        self.timeout = timeout
        self.keys_dir = keys_dir
        create_keys(self.keys_dir)

    def load_keys(self):
        import zmq

        public_key, secret_key = zmq.auth.load_certificate(
            os.path.join(self.keys_dir, "node.key_secret")
        )
        return public_key, secret_key

    def new_socket(self, context, poll):
        import zmq

        public_key, secret_key = self.load_keys()
        client = context.socket(zmq.REQ)
        client.curve_publickey = public_key
        client.curve_secretkey = secret_key
        client.curve_serverkey = self.server_key
        server_endpoint = "tcp://%s:%i" % (self.host, self.port)
        # print('connecting to', server_endpoint)
        client.connect(server_endpoint)
        poll.register(client, zmq.POLLIN)
        return client

    def parse_ffs(self, ffs):
        if ffs.endswith("/"):
            return ffs[:-1]
        else:
            return ffs

    def call_central(self, msg, timeout=None):
        if timeout is None:
            timeout = self.timeout
        if not "msg" in msg:
            raise ValueError("invalid message", msg)
        import zmq
        import zmq.auth
        import json

        request = json.dumps(msg).encode("utf-8")
        context = zmq.Context(1)  # number of threads
        poll = zmq.Poller()
        client = self.new_socket(context, poll)
        retries_left = 1
        sequence = 0
        while retries_left:
            sequence += 1
            request = json.dumps(msg).encode("utf-8")
            client.send(request)
            reply = None
            expect_reply = True
            while expect_reply:
                socks = dict(poll.poll(timeout))
                if socks.get(client) == zmq.POLLIN:
                    reply = client.recv()
                    if reply:
                        retries_left = 0
                        client.setsockopt(zmq.LINGER, 0)
                        client.close()
                        poll.unregister(client)
                        if reply.startswith(b"OK"):
                            reply = reply[3:]
                            reply = reply.decode("utf-8")
                            reply = json.loads(reply)
                        else:
                            pass
                        break
                else:
                    timeout *= 2
                    # Socket is confused. Close and remove it.
                    client.setsockopt(zmq.LINGER, 0)
                    client.close()
                    poll.unregister(client)
                    retries_left -= 1
                    if retries_left == 0:
                        break
                    # Create new connection
                    client = self.new_socket(context, poll)
                    client.send(request)
        context.term()
        if reply is None:
            raise ValueError(
                "No reply from server (%s:%s). Aborting" % (self.host, self.port)
            )
        if reply.startswith(b"GZIP"):
            reply = gzip.decompress(reply[4:])
        reply = json.loads(reply.decode("utf-8"))
        return reply

    def dispatch(self, args, parser):
        cmd = args.command
        cmd = {
            "ls": "list_ffs",
            "q": "service_que",
        }.get(cmd, cmd)
        func_name = "cmd_" + cmd
        if hasattr(self, func_name):
            getattr(self, func_name)(args)
        else:
            raise ValueError("Invalid command: %s" % args.command)

    def call_and_print(self, cmd):
        self.print_engine_results(self.call_central(cmd))

    def print_engine_results(self, reply):
        print(json.dumps(reply, indent=4, sort_keys=True))
        if "error" not in reply:
            sys.exit(0)
        else:
            sys.exit(2)

    def cmd_list_ffs(self, args):
        self.load_ffs_list()
        if args.json:
            print(json.dumps(self.ffs_list, indent=4, sort_keys=True))
        else:
            for key, targets in sorted(self.ffs_list.items()):
                if args.filter:
                    show = False
                    for f in args.filter:
                        if f.lower() in key.lower():
                            show = True
                            break
                else:
                    show = True
                if show:
                    print("%s\t%s" % (key, ", ".join([str(x) for x in targets])))

    def fix_orphans(self, ffs_list, targets):
        import random

        def iter_parents(ffs):
            if ffs.startswith("/"):
                ffs = ffs[1:]
            suffix, _ = os.path.split(ffs)
            while suffix:
                yield suffix
                suffix, _ = os.path.split(suffix)

        def calc():
            orphans = [
                node for (node, targets) in ffs_list.items() if len(targets) == 1
            ]
            for ffs in sorted(orphans):
                main = ffs_list[ffs][0]  # and there only should ever be one main
                available = [x for x in targets if x not in main]
                if not available:
                    raise ValueError(
                        "No target after substracting main. Add another --fix parameter"
                    )

                new_target = random.choice(available)
                for parent in reversed(list(iter_parents(ffs))):
                    if new_target not in ffs_list[parent]:
                        yield (parent, new_target)
                yield (ffs, new_target)

        import collections

        ordered = collections.OrderedDict([(x, 1) for x in calc()])
        return list(ordered.keys())

    def cmd_list_orphans(self, args):
        reply = self.call_central({"msg": "list_ffs"})
        result = []
        for node, targets in reply.items():
            if len(targets) == 1:
                result.append(node)
        if args.filter:
            filtered = []
            for r in result:
                for f in args.filter:
                    if f.lower() in r.lower():
                        filtered.append(r)
            result = filtered
        if args.fix:
            targets = args.fix
            for ffs, new_target in self.fix_orphans(result, reply, targets):
                print("ffs.py add_targets %s %s" % (ffs, new_target))
        else:
            print(json.dumps(result, indent=4, sort_keys=True))

    def cmd_service(self, args):
        args.command = "service_" + args.service_command
        self.dispatch(args)

    def cmd_service_is_started(self, args):
        self.call_and_print({"msg": "service_is_started"})

    def cmd_service_restart(self, args):
        self.call_and_print({"msg": "service_restart"})

    def render_que(self, que):
        def pf(x):
            x["runtime"] = "%.2fs" % x["runtime"]
            if "storage_prefix" in x["msg"]:
                del x["msg"]["storage_prefix"]
            return x

        for key in que:
            que[key] = [pf(x) for x in que[key]]
        pprint.pprint(que)

    def cmd_service_que(self, args):
        self.call_and_print({"msg": "service_que"})

    def cmd_service_inspect_model(self, args):
        self.call_and_print({"msg": "service_inspect_model"})

    def cmd_service_list_disks(self, args):
        self.call_and_print({"msg": "service_list_disks"})

    def cmd_service_capture_all_if_changed(self, args):
        self.call_and_print({"msg": "service_capture_all_if_changed"})

    def render_error(self, reply):
        pprint.pprint(reply)
        sys.exit(1)

    def cmd_service_que_current(self, args):
        reply = self.call_central({"msg": "service_que"})
        if "error" in reply:
            self.render_error(reply)

        filtered = {}
        for key, values in reply.items():
            filtered[key] = [x for x in values if x["status"] == "in_progress"]
        self.render_que(filtered)

    def cmd_service_install(self, args):
        FFS_Installer(self).install(self.keys_dir)

    def cmd_service_free_space(self, args):
        print("Free space at engine startup")
        full_info = self.call_central(({"msg": "list_ffs", "full": True}))
        by_target = {}
        for ffs, ffs_info in full_info.items():
            for target, props in ffs_info["properties"].items():
                if not "available" in props:  # happens on new ffs
                    continue
                av = props["available"]
                av = to_bytes(av)
                if not target in by_target:
                    by_target[target] = av
                else:
                    by_target[target] = max(av, by_target[target])
        longest = max([len(t) for t in by_target])
        no_length = 10
        print("%s\t%s\t" % ("target".ljust(longest), "free".rjust(no_length)))
        for t in sorted(by_target):
            print(
                "%s\t%s" % (t.ljust(longest), sizeof_fmt(by_target[t]).rjust(no_length))
            )

    def get_targets(self):
        return self.call_central({"msg": "list_targets"})

    def cmd_list_targets(self, args):
        return self.print_engine_results(self.get_targets())

    def expand_targets(self, ffs, targets):
        targets = [x.strip() for x in targets]
        for x in targets:
            if x == ":all":
                return self.get_targets()
            elif x == ":parents":
                self.load_ffs_list()
                parent_name = ffs[: ffs.rfind("/")]
                return self.ffs_list[parent_name]
        return targets

    def cmd_new(self, args):
        ffs = args.name
        targets = self.expand_targets(ffs, args.targets)
        self.call_and_print({"msg": "new", "ffs": ffs, "targets": targets})

    def cmd_rename_ffs(self, args):
        ffs = self.parse_ffs(args.ffs_from[0])
        new_name = self.parse_ffs(args.ffs_to[0])
        self.call_and_print({"msg": "rename", "ffs": ffs, "new_name": new_name})

    def cmd_capture(self, args):
        if args.ffs is None:
            path = os.path.abspath(os.getcwd())
        else:
            path = self.parse_ffs(args.ffs)
        ffs, sub_path = self.find_current_ffs_and_sub_path(path)

        self.call_and_print(
            {
                "msg": "capture" if not args.if_changed else "capture_if_changed",
                "ffs": ffs,
                "chown_and_chmod": args.chown_and_chmod,
                "postfix": args.postfix if args.postfix else "",
            }
        )

    def cmd_remove_target(self, args):
        self.call_and_print(
            {
                "msg": "remove_target",
                "ffs": self.parse_ffs(args.ffs),
                "target": args.target[0].strip(),
            }
        )

    def cmd_add_targets(self, args):
        self.call_and_print(
            {
                "msg": "add_targets",
                "ffs": self.parse_ffs(args.ffs),
                "targets": [x.strip() for x in args.targets],
            }
        )

    def cmd_move(self, args):
        self.call_and_print(
            {
                "msg": "move_main",
                "ffs": self.parse_ffs(args.ffs),
                "target": args.target.strip(),
            }
        )

    def load_ffs_list(self):
        if not hasattr(self, "ffs_list"):
            self.ffs_list = self.call_central(({"msg": "list_ffs"}))
            if "error" in self.ffs_list:
                print(self.ffs_list)
                raise ValueError("load_ffs_list_failed")

    def find_current_ffs_and_sub_path(self, path):
        self.load_ffs_list()
        if path in self.ffs_list:
            ffs = path
            sub_path = "/"
        else:
            if not path.startswith("/"):  # an absolute path
                path = os.path.abspath(path)
            if not path.endswith("/"):
                path += "/"
            # order by length, descending
            for ffs in reversed(sorted(self.ffs_list.keys(), key=lambda x: len(x))):
                if "/" + ffs + "/" in path:
                    sub_path = path[path.find("/" + ffs + "/") + len("/" + ffs) :]
                    if sub_path.endswith("/") and not sub_path == "/":
                        sub_path = sub_path[:-1]
                    break
            else:
                raise ValueError(
                    "could not identify ffs from path - probably not within an ffs.: '%s'. FFS:%s"
                    % (path, self.ffs_list.keys())
                )
        return ffs, sub_path

    def cmd_chown(self, args):
        if args.ffs is None:
            path = os.path.abspath(os.getcwd())
        else:
            path = self.parse_ffs(args.ffs)
        ffs, sub_path = self.find_current_ffs_and_sub_path(path)

        self.call_and_print(
            {"msg": "chown_and_chmod", "ffs": ffs, "sub_path": sub_path}
        )

    def cmd_set_snapshot_interval(self, args):
        ffs = self.parse_ffs(args.ffs)
        interval = args.interval
        if interval == "off":
            interval = 0
        else:
            if interval.endswith("s"):
                interval = int(interval[:-1])
            elif interval.endswith("m"):
                interval = int(interval[:-1]) * 60
            elif interval.endswith("h"):
                interval = int(interval[:-1]) * 60 * 60
            elif interval.endswith("d"):
                interval = int(interval[:-1]) * 60 * 60 * 24
            else:
                raise ValueError(
                    "interval must conform to [0-9]+[smhd] for seconds/minutes/hours/days"
                )
            if interval < 60:
                raise ValueError("Interval must be larger than 60s")

        self.call_and_print(
            {"msg": "set_snapshot_interval", "ffs": ffs, "interval": interval}
        )

    def cmd_set_priority(self, args):
        ffs = self.parse_ffs(args.ffs)
        priority = args.priority
        if priority == "-":
            pass
        else:
            priority = int(priority)
        self.call_and_print({"msg": "set_priority", "ffs": ffs, "priority": priority})

    def cmd_rollback(self, args):
        ffs = self.parse_ffs(args.ffs)
        snapshots = self.call_central({"msg": "list_snapshots", "ffs": ffs})
        if "error" in snapshots:
            print("Error retrieving snapshots", snapshots)
            sys.exit(1)
        if snapshots:
            snapshots = snapshots["snapshots"]
            print("Choose a snapshot by number<enter>, or abort with ctrl-c")
            for ii, sn in enumerate(snapshots):
                print(ii + 1, sn)
            chosen = int(sys.stdin.readline()) - 1
            if chosen < 0 or chosen >= len(snapshots):
                raise ValueError("Invalid number entered")
            self.call_and_print(
                {"msg": "rollback", "ffs": ffs, "snapshot": snapshots[ii]}
            )
        else:
            print("No snapshots available")
            sys.exit(1)

    def _format_time_interval(self, seconds):
        hours = seconds // 3600
        seconds = seconds - (hours * 3600)
        minutes = seconds // 60
        seconds = seconds - (minutes * 60)
        return "%sh %s m%ss" % (hours, minutes, seconds)

    def cmd_service_list_intervals(self, args):
        full_info = self.call_central(({"msg": "list_ffs", "full": True}))
        if "error" in full_info:
            print(full_info)
            sys.exit(1)
        for ffs, ffs_info in full_info.items():
            main = ffs_info["targets"][0]
            if main == "NoMainAvailable":
                continue
            main_props = ffs_info["properties"][main]
            iv = main_props.get("ffs:snapshot_interval", "-")
            if iv != "-":
                print(ffs, "every", self._format_time_interval(int(iv)))

    def cmd_service_space_hogs(self, args):
        full_info = self.call_central(({"msg": "list_ffs", "full": True}))
        by_ffs = []
        for ffs, ffs_info in full_info.items():
            try:
                main = ffs_info["targets"][0]
                if (
                    args.restrict_to_host is None
                    or args.restrict_to_host in ffs_info["targets"]
                ):
                    usedbydataset = to_bytes(
                        ffs_info["properties"][main]["usedbydataset"]
                    )
                    by_ffs.append((usedbydataset, ffs, main, len(ffs_info["targets"])))
            except:
                # print("cause")
                # print(ffs)
                import pprint

                pprint.pprint(full_info)
                raise
        by_ffs.sort()
        by_ffs.reverse()
        print("Used by dataset (at engine startup")
        print("size\tffs\tmain\tcount")
        for size, ffs, main, count in by_ffs:
            print("%s\t%s\t%s\t%i" % (sizeof_fmt(size).ljust(10), ffs, main, count))

    def cmd_service_main_disk_usage(self, args):
        full_info = self.call_central(({"msg": "list_ffs", "full": True}))
        by_main = collections.Counter()
        for ffs, ffs_info in full_info.items():
            try:
                main = ffs_info["targets"][0]
                usedbydataset = to_bytes(ffs_info["properties"][main]["usedbydataset"])
                by_main[main] += usedbydataset
            except:
                # print("cause")
                # print(ffs)
                import pprint

                pprint.pprint(full_info)
                raise
        print("Used by dataset (main only,  at engine startup)")
        print("Host\tUsed\t")
        ll = max((len(x) for x in by_main))
        for host, size in by_main.items():
            print("%s\t%s" % (host.ljust(ll), sizeof_fmt(size).rjust(15)))
        print("")
        print(
            "%s\t%s"
            % ("Total".ljust(ll), (sizeof_fmt(sum(by_main.values())).rjust(15)))
        )

    def cmd_service_disk_usage(self, args):
        full_info = self.call_central(({"msg": "list_ffs", "full": True}))
        by_main = collections.Counter()
        for ffs, ffs_info in full_info.items():
            try:

                for target in ffs_info["targets"]:
                    usedbydataset = to_bytes(
                        ffs_info["properties"][target]["usedbydataset"]
                    )
                    by_main[target] += usedbydataset
            except:
                # print("cause")
                # print(ffs)
                import pprint

                pprint.pprint(full_info)
                raise
        print("Used by dataset (total, at engine startup")
        print("Host\tUsed\t")
        ll = max((len(x) for x in by_main))
        for host, size in by_main.items():
            print("%s\t%s" % (host.ljust(ll), sizeof_fmt(size).rjust(15)))
        print("")
        print(
            "%s\t%s"
            % ("Total".ljust(ll), (sizeof_fmt(sum(by_main.values())).rjust(15)))
        )

    def cmd_service_snapshot_usage(self, args):
        full_info = self.call_central(({"msg": "list_ffs", "full": True}))
        by_main = collections.Counter()
        for ffs, ffs_info in full_info.items():
            try:

                for target in ffs_info["targets"]:
                    usedbydataset = to_bytes(
                        ffs_info["properties"][target]["usedbysnapshots"]
                    )
                    by_main[target] += usedbydataset
            except:
                # print("cause")
                # print(ffs)
                import pprint

                pprint.pprint(full_info)
                raise
        print("Used by dataset (snapshots, at engine startup")
        print("Host\tUsed\t")
        ll = max((len(x) for x in by_main))
        for host, size in by_main.items():
            print("%s\t%s" % (host.ljust(ll), sizeof_fmt(size).rjust(15)))
        print("")
        print(
            "%s\t%s"
            % ("Total".ljust(ll), (sizeof_fmt(sum(by_main.values())).rjust(15)))
        )

    def cmd_service_snapshot_hogs(self, args):
        full_info = self.call_central(({"msg": "list_ffs", "full": True}))
        by_ffs = []
        for ffs, ffs_info in full_info.items():
            print(ffs_info)
            main = ffs_info["targets"][0]
            usedbydataset = to_bytes(ffs_info["properties"][main]["usedbysnapshots"])
            by_ffs.append((usedbydataset, ffs))
        by_ffs.sort()
        by_ffs.reverse()
        print("Used by snapshots (at engine startup")
        print("size\tffs")
        for size, ffs in by_ffs:
            print("%s\t%s" % (sizeof_fmt(size).ljust(10), ffs))

    def cmd_service_main_less(self, args):
        full_info = self.call_central(({"msg": "list_ffs", "full": True}))
        by_ffs = []
        print("FFS missing a main")
        print("ffs\tTargets")
        for ffs, ffs_info in full_info.items():
            main = ffs_info["targets"][0]
            if main == "NoMainAvailable":
                print(ffs, " ".join(ffs_info["targets"][1:]), sep="\t")


def iterate_parent_paths(path):
    parts = path.split("/")
    for i in reversed(range(2, len(parts) + 1)):
        yield "/".join(parts[:i])

def load_key(keystr):
    if keystr.startswith('/'):
        return Path(keystr).read_text().encode('ascii')
    else:
        return keystr.encode("ascii")

def dispatch_args(args, parser):
    c = FFSClient(
        args.host if args.host else FFS_CONFIG["host"],
        args.port if args.port else FFS_CONFIG["port"],
        (args.server_key if args.server_key else load_key(FFS_CONFIG["key"])),
        FFS_CONFIG.get("certificate_dir", "/home/ffs/certificates"),
        int(args.timeout) if args.timeout else 2500,
    )
    c.dispatch(args, parser)
    sys.exit(0)


class SmartFormatter(argparse.HelpFormatter):
    def _split_lines(self, text, width):
        if text.startswith("R|"):
            return text[2:].splitlines()
        # this is the RawTextHelpFormatter._split_lines
        return argparse.HelpFormatter._split_lines(self, text, width)


class FFSArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs["formatter_class"] = SmartFormatter
        # argparse.ArgumentParser.__init__(self, *args, **kwargs)
        super().__init__(*args, **kwargs)


def build_parser(server_opts_only=False):
    parser = FFSArgumentParser(
        description="Command line interface to command the ffs central"
    )
    parser.add_argument("--host", help="FFS central host to contact", action="store")
    parser.add_argument("--port", help="FFS central port", action="store", type=int)
    parser.add_argument("--server_key", help="FFS central secret key", action="store")
    parser.add_argument(
        "--timeout",
        help="How long to wait for a reply (in ms)",
        action="store",
        default=3000,
    )

    if server_opts_only:
        return parser

    sub_parsers = parser.add_subparsers(
        title="command",
        help="sub_command help",
        dest="command",
        parser_class=FFSArgumentParser,
    )

    new_parser = sub_parsers.add_parser("new", help="add a new ffs")
    new_parser.add_argument(
        "name",
        help="path relative to /machine/ffs/ of the newly created ffs",
        action="store",
    )
    new_parser.add_argument(
        "targets",
        help="store new ffs on these machines. See list_targets for a list. Seperated by space",
        default=None,
        nargs="*",
    )

    list_parser = sub_parsers.add_parser(
        "list_ffs", help="list all ffs", aliases=["ls"]
    )
    list_parser.add_argument(
        "filter",
        help="matching any of the words given in path or any of the targets (targets start with :)",
        nargs="*",
        action="store",
    )
    list_parser.add_argument("--json", help="json output", action="store_true")

    list_orphans_parser = sub_parsers.add_parser(
        "list_orphans", help="list all ffs that are not replicated"
    )
    list_orphans_parser.add_argument(
        "filter",
        help="matching any of the words given in path or any of the targets (targets start with :)",
        nargs="*",
        action="store",
    )
    list_orphans_parser.add_argument(
        "--fix",
        help='print add_targets statements, needs at least two, comma-seperated target machines to work with, e.g. "--fix=rose amy" since it has to remove the current main',
        action="append",
    )

    list_targets_parser = sub_parsers.add_parser(
        "list_targets", help="list all available targets"
    )

    capture_parser = sub_parsers.add_parser(
        "capture", help="snapshot (and transmit to targets)"
    )
    capture_parser.add_argument(
        "ffs", help="ffs relative path", action="store", nargs="?"
    )
    capture_parser.add_argument(
        "--chown_and_chmod",
        help="Chown and chmod to default before capture",
        action="store_true",
    )
    capture_parser.add_argument(
        "--postfix", help="Chown and chmod to default before capture", action="store"
    )
    capture_parser.add_argument(
        "--if_changed", help="Capture only if changed", action="store_true"
    )

    chown_parser = sub_parsers.add_parser(
        "chown", help="chown and chmod ffs/current folder within ffs"
    )
    chown_parser.add_argument(
        "ffs", help="ffs relative path, or absolute path", action="store", nargs="?"
    )

    add_target_parser = sub_parsers.add_parser(
        "add_targets", help="add one ore more targets to an existing ffs"
    )
    add_target_parser.add_argument("ffs", help="ffs name", action="store")
    add_target_parser.add_argument(
        "targets", help="one or multiple targets (see list-targets)", nargs="+"
    )

    remove_target_parser = sub_parsers.add_parser(
        "remove_target", help="remove a target from an ffs"
    )
    remove_target_parser.add_argument("ffs", help="ffs relative path", action="store")
    remove_target_parser.add_argument("target", help="target to remove", nargs=1)

    rename_parser = sub_parsers.add_parser("rename_ffs", help="rename an existing ffs")
    rename_parser.add_argument(
        "ffs_from", help="ffs relative path", action="store", nargs=1
    )
    rename_parser.add_argument(
        "ffs_to", help="ffs relative path", action="store", nargs=1
    )

    move_parser = sub_parsers.add_parser("move", help="move main to another ffs")
    move_parser.add_argument("ffs", help="ffs relative path", action="store")
    move_parser.add_argument("target", help="new main host", action="store")

    set_snapshot_interval_parser = sub_parsers.add_parser(
        "set_snapshot_interval", help="set automatic (time based) snapshot interval"
    )
    set_snapshot_interval_parser.add_argument(
        "ffs", help="ffs relative path", action="store"
    )
    set_snapshot_interval_parser.add_argument(
        "interval", help="interval in minutes (or off to disable)", action="store"
    )

    set_priority = sub_parsers.add_parser(
        "set_priority", help="set priority - lower priority get's captured & send first"
    )
    set_priority.add_argument("ffs", help="ffs relative path", action="store")
    set_priority.add_argument(
        "priority", help="number, lower is sooner. Default is 1000", action="store"
    )

    rollback_parser = sub_parsers.add_parser(
        "rollback", help="rollback to an earlier snapshot, trashing all newer snapshots"
    )
    rollback_parser.add_argument("ffs", help="ffs relative path", action="store")

    service_choices = [
        (
            "que",
            "list currently ongoing and planned processing",
            {},
            {"aliases": ["q"]},
        ),
        ("que_current", "list currently ongoing processing"),
        ("restart", "restart central (and abor all current processing)"),
        ("install", "install on this machine"),
        ("is_started", "is the engine startup done?"),
        ("list_intervals", "list ffs that have interval based snapshots"),
        (
            "free_space",
            "how much space (as reported by zfs list on ffs:root) has each target available",
        ),
        (
            "space_hogs",
            "find ffs that use a lot of disk space",
            {
                "dest": "restrict_to_host",
                "help": "restrict to host (optional)",
                "nargs": "?",
                "action": "store",
            },
        ),
        ("main_disk_usage", "how much space do the main copies use (excl. snapshots)"),
        ("disk_usage", "how much space do the copies use (excl. snapshots)"),
        ("snapshot_usage", "how much disk space is used by snapshots"),
        ("snapshot_hogs", "find ffs that use a lot of disk space in snapshots"),
        (
            "inspect_model",
            "inspect the current model of the FFS (ie. what do you know?)",
        ),
        (
            "capture_all_if_changed",
            "run capture --if_changed on every ffs (loop provided by central engine)",
        ),
        (
            "list_disks",
            "list all disks in zpools on all machines and their sizes (in bytes)",
        ),
        ("main_less", "identify ffs that do not have a main"),
    ]
    for entry in service_choices:
        name, help, *other_args = entry
        if len(other_args) > 1:
            kwargs = other_args[1]
        else:
            kwargs = {}
        service = sub_parsers.add_parser("service_" + name, help=help, **kwargs)
        if len(other_args):
            if other_args[0]:
                service.add_argument(**other_args[0])
    return parser


def _complete_targets(c, word):
    for x in c.get_targets():
        if x.startswith(word):
            print(x)
    sys.exit(0)


def _complete_ffs(c, word, prefix_only=False):
    c.load_ffs_list()
    l = c.ffs_list.keys()
    if prefix_only:
        l = sorted(set([os.path.split(x)[0] for x in l]))
        l = [x for x in l if x]
    for x in l:
        if x.startswith(word):
            print(x)
    sys.exit(0)


def _complete_missing_targets(c, ffs, word):
    c.load_ffs_list()
    if ffs in c.ffs_list:
        already = set(c.ffs_list[ffs])
    else:
        already = set()
    targets = c.get_targets()
    ok_targets = set(targets).difference(already)
    for x in ok_targets:
        if x.startswith(word):
            print(x)
    sys.exit(0)


def _complete_non_main_targets(c, ffs, word):
    c.load_ffs_list()
    if ffs in c.ffs_list:
        for x in c.ffs_list[ffs][1:]:
            if x.startswith(word):
                print(x)
    sys.exit(0)


def auto_complete(parser):
    server_opts_parser = build_parser(server_opts_only=True)
    parts = re.split("\s", sys.argv[-1])
    args, remainder = server_opts_parser.parse_known_args(parts)
    load_config()
    c = FFSClient(
        args.host if args.host else FFS_CONFIG["host"],
        args.port if args.port else FFS_CONFIG["port"],
        (args.server_key if args.server_key else FFS_CONFIG["key"]).encode("ascii"),
        timeout=300,
    )
    so_far = remainder[1:]
    if so_far and so_far[0] == "new":
        words = so_far[1:]
        if len(words) > 1:
            _complete_targets(c, words[-1])
        elif len(words) == 1:
            _complete_ffs(c, words[-1], True)
    elif so_far and so_far[0] == "add_targets":
        words = so_far[1:]
        if len(words) < 2:
            _complete_ffs(c, so_far[-1])
        else:
            ffs = words[0]
            _complete_missing_targets(c, ffs, words[-1])
    elif so_far and so_far[0] == "remove_target":
        words = so_far[1:]
        if len(words) < 2:
            _complete_ffs(c, so_far[-1])
        elif len(words) == 2:
            ffs = words[0]
            _complete_non_main_targets(c, ffs, words[-1])
    elif so_far and so_far[0] == "move":
        words = so_far[1:]
        if len(words) < 2:
            _complete_ffs(c, so_far[-1])
        else:
            ffs = words[0]
            _complete_non_main_targets(c, ffs, words[-1])
    elif so_far and so_far[0] in (
        "set_snapshot_interval",
        "set_priority",
        "chown",
        "rename_ffs",
        "capture",
    ):
        _complete_ffs(c, so_far[-1])
    # elif so_far and so_far[0] == 'service':
    # for x in service_choices:
    # word = so_far[1]
    # if x[0].startswith(word):
    # print(x[0])
    else:
        for a in parser._actions:
            if isinstance(a, argparse._SubParsersAction):
                for name, subparser in a.choices.items():
                    if name.startswith(so_far[0]):
                        print("%s\t%s" % (name, ""))
            elif isinstance(a, argparse._StoreAction):
                name = a.option_strings[0]
                if name.startswith(so_far[0]):
                    print("%s\t%s" % (name, a.help))


def robust_rights(filename):
    import stat

    filename = Path(filename)
    try:
        stats = filename.stat()
        owner = stats.st_uid
        gid = stats.st_gid
        rights = stat.filemode(stats.st_mode)[1:]
    except PermissionError:
        raw = (
            subprocess.check_output(
                ["sudo", "stat", str(filename.absolute()), "-c", "%A\n%u\n%g"]
            )
            .decode("utf-8")
            .split("\n")
        )
        rights = raw[0][1:]
        owner = int(raw[1])
        gid = int(raw[2])
    return (rights, owner, gid)


def check_user_group_ffs(allow_root):
    uid = os.getuid()
    groups = (
        subprocess.check_output(["id", "-Gn", str(uid)])[:-1].decode("utf-8").split(" ")
    )
    if not "ffs_client" in groups and not (allow_root and uid == 0):
        raise ValueError(
            f"Your user {uid} is not in the ffs_client group, groups was {groups}."
        )


def main():
    check_user_group_ffs("service_install" in sys.argv)
    parser = build_parser()
    if "--_completion" in sys.argv:
        auto_complete(parser)
    else:
        args = parser.parse_args()
        if args.command is None:
            parser.print_usage()
            sys.exit(1)
        else:
            load_config()
            dispatch_args(args, parser)


if __name__ == "__main__":
    main()

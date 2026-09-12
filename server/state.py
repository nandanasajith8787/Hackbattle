class FakeFS:
    def __init__(self):
        # Starting fake filesystem — every session starts here
        self.cwd = "/home/deploy"
        self.files = {
            "/home/deploy": ["readme.txt", ".bash_history", "credentials.txt"]  # <- bait file
        }
        self.contents = {
            "/home/deploy/readme.txt": "Welcome to prod-server-03. Contact ops@internal.co for access issues.",
            "/home/deploy/credentials.txt": "db_user=admin\ndb_pass=Winter2024!"
        }

    def apply(self, command: str):
        """Update fake state based on the command the attacker typed."""
        parts = command.strip().split()
        if not parts:
            return

        cmd = parts[0]

        if cmd == "touch" and len(parts) > 1:
            self.files.setdefault(self.cwd, [])
            if parts[1] not in self.files[self.cwd]:
                self.files[self.cwd].append(parts[1])
                full_path = self.cwd.rstrip("/") + "/" + parts[1]
                self.contents[full_path] = ""   # new file starts empty

        elif cmd == "mkdir" and len(parts) > 1:
            new_dir = parts[1].rstrip("/")
            self.files.setdefault(self.cwd, [])
            if new_dir + "/" not in self.files[self.cwd]:
                self.files[self.cwd].append(new_dir + "/")
            full_path = self.cwd.rstrip("/") + "/" + new_dir
            self.files.setdefault(full_path, [])

        elif cmd == "cd" and len(parts) > 1:
            target = parts[1]
            if target == "..":
                self.cwd = "/".join(self.cwd.rstrip("/").split("/")[:-1]) or "/"
            elif target.startswith("/"):
                self.cwd = target
            else:
                self.cwd = self.cwd.rstrip("/") + "/" + target

        elif cmd == "rm" and len(parts) > 1:
            target = parts[1]
            if self.cwd in self.files and target in self.files[self.cwd]:
                self.files[self.cwd].remove(target)
                full_path = self.cwd.rstrip("/") + "/" + target
                self.contents.pop(full_path, None)

        elif cmd == "cat" and len(parts) > 1:
            pass  # no state change, but useful hook if you later track file contents

        # currently silently does nothing if file doesn't exist — that's fine,
        # a real bash would print "rm: cannot remove 'x': No such file or directory"
        # but that error text will actually come from the LLM (Person 2's job), not here

    def snapshot(self) -> dict:
        """Return current state — this is what gets sent to the LLM for context."""
        return {
            "cwd": self.cwd,
            "files": self.files,
            "contents": self.contents
        }

    def check_bait_accessed(self, command: str) -> bool:
        """Returns True if attacker touched the honeytoken bait file."""
        return "credentials.txt" in command
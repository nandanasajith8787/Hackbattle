from state import FakeFS

fs = FakeFS()
print(fs.snapshot())

fs.apply("touch hack.sh")
print(fs.snapshot())

fs.apply("mkdir tools")
fs.apply("cd tools")
print(fs.snapshot())

fs.apply("cd ..")
print(fs.snapshot())

fs.apply("cat readme.txt")
print(fs.snapshot())
print(fs.snapshot())
print("Bait accessed?", fs.check_bait_accessed("cat credentials.txt"))
print("\n--- Multi-session isolation test ---")
fs1 = FakeFS()
fs2 = FakeFS()

fs1.apply("touch attacker1_file.sh")
fs1.apply("mkdir secret_folder")

print("fs1 state:", fs1.snapshot())
print("fs2 state:", fs2.snapshot())

# fs2 should NOT contain attacker1_file.sh or secret_folder
assert "attacker1_file.sh" not in fs2.snapshot()["files"]["/home/deploy"], "FAIL: state leaked between sessions!"
assert "secret_folder/" not in fs2.snapshot()["files"]["/home/deploy"], "FAIL: state leaked between sessions!"
print("PASS: sessions are correctly isolated")
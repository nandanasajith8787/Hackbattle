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
import pwn

if __name__ == "__main__":

    # I run the process.
    # process_to_exploit = pwn.remote("csc748.hostbin.org", 7021)
    # This next line can replace the one above for testing against a local binary.
    process_to_exploit = pwn.process("./lab2-1.bin")

    # Now I can drop into a shell.
    process_to_exploit.interactive()
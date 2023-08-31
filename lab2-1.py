import pwn

if __name__ == "__main__":
    
    process_to_exploit = pwn.remote("csc748.hostbin.org", 7021)
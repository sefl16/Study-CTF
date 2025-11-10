

### Stabalize shells

```bash
# Method 1: Python
# Step 1: Spawn a better shell using python
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Step 2: xterm
export TERM=xterm

# Step 3: Press ctrl + Z to background the shell

# Step 4: Insert one-liner
stty raw -echo; fg; ls; export SHELL=/bin/bash; export=screen; stty rows 38 columns 116; reset;

# Step 5: When exiting the shell type reset and press enter

```

```bash

# Method 2: Use rlwrap on netcat
rlwrap nc -nlvnp <port>

```
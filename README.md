# XDP/BPF TCP Header Options Parsing
## Description
A repository to show attempts at dynamically parsing the TCP header options (specifically timestamps in this repository) within XDP/BPF.

## Command Line Options
There are two command line options for this program which may be found below.

* `-i --interface` => The interface name to attempt to attach the XDP program to (**required**).
* `-o --obj` => A path to the BPF object file (default is `/etc/tcpopts/xdp.o` which `make install` installs to).

## Building
You may use the following to build the program.

```
# Clone the repository and libbpf (with the --recursive flag).
git clone --recursive https://github.com/gamemann/XDP-TCP-Header-Options.git

# Change directory to the repository.
cd XDP-TCP-Header-Options/

# Build the program.
make

# Install the program. The program is installed to /usr/bin/tcpopts
sudo make install
```

## Credits
* [Christian Deacon](https://github.com/gamemann)
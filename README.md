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

## Fails
The current code fails with the following:

```
49: (2d) if r6 > r2 goto pc+24
 R0_w=inv2 R1=pkt(id=0,off=0,r=34,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3=pkt(id=1,off=34,r=36,umax_value=60,var_off=(0x0; 0x3c)) R4=inv41 R5_w=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R6_w=pkt(id=258,off=35,r=0,umax_value=65595,var_off=(0x0; 0x1ffff)) R7_w=pkt(id=258,off=34,r=0,umax_value=65595,var_off=(0x0; 0x1ffff)) R10=fp0
50: (71) r7 = *(u8 *)(r7 +0)
invalid access to packet, off=34 size=1, R7(id=258,off=34,r=0)
R7 offset is outside of the packet
processed 8789 insns (limit 1000000) max_states_per_insn 4 total_states 142 peak_states 142 mark_read 4

libbpf: -- END LOG --
libbpf: failed to load program 'xdp_prog'
libbpf: failed to load object '/etc/tcpopts/xdp.o'
Error loading BPF program.
```

The full log may be found in the `logs/` directory.

The error is caused by this piece of code:

```C
// This check shouldn't be needed, but just for safe measure, perform another check before incrementing optdata by the option's length.
if (len <= (__u8 *)data_end && len >= (__u8 *)data)
{
    optdata += (*len > 0) ? *len : 1;
}
else
{
    // Avoid an infinite loop.
    optdata++;
}
```

If you stop incrementing `optdata` by `*len`, the XDP program loads. For example:

```C
if (len <= (__u8 *)data_end && len >= (__u8 *)data)
{
    optdata++;
}
else
{
    // Avoid an infinite loop.
    optdata++;
}
```

Loads without any issues.

## Other Notes
I found an article [here](https://legacy.netdevconf.info/0x14/pub/slides/50/Issuing%20SYN%20Cookies%20in%20XDP.pdf) where it appears the creator was having similar issues. At the end, under challenges/next steps you can see:

> Parsing variable number of TCP options is challenging for the verifier

Being able to parse TCP header options in XDP/BPF would be very useful in my opinion. The code I have right now has many checks that I don't think are needed, but I'm not able to tell the BPF verifier the code is safe/within the packet range for some reason when incrementing by a dynamic value.

## Credits
* [Christian Deacon](https://github.com/gamemann)
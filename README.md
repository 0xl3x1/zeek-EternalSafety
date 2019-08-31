zeek-EternalSafety
==================

*EternalSafety* is a Zeek/Bro package for detecting potentially-dangerous SMBv1
protocol violations, including those leveraged by the infamous
[Eternal*](https://en.wikipedia.org/wiki/EternalBlue) family of Windows
exploits. However, rather than identifying these exploits via simple
signature-matching, *EternalSafety* instead implements a set of SMBv1 protocol
invariants that encapsulate techniques used by each Eternal* exploit to trigger
bugs in unpatched Windows systems. 

*EternalSafety* accurately and reliably identifies the EternalBlue,
EternalSynergy and EternalRomance exploits, and the DoublePulsar backdoor
implant. Due to limitations in Zeek's SMBv1 support, it has limited support for
detecting EternalChampion via signature-matching. *EternalSafety* also
identifies a range of other protocol violations, such as the use of
unimplemented/unused SMBv1 commands, server-initiated changes in values that
may only be set by an SMBv1 client, incorrect interleaving of transaction
types, incorrect ordering of transaction messages, and sending more data as
part of a transaction than was specified in the transaction request.

The key idea behind this package comes from an observation that in order to
trigger bugs that leak memory, overflow buffers, rewrite function pointers,
etc., all of the Eternal* exploits are forced to violate parts of the SMBv1
protocol specification.

Unlike existing detections for the Eternal* exploits, *EternalSafety* does NOT
take a solely signature-based approach. Instead, it implements a **superset**
of more general invariants selected from the SMBv1 protocol specification. This
is a powerful distinction: in addition to detecting the known Eternal*
exploits, ***EternalSafety* may also be able to detect the use of new,
yet-to-be-identified SMBv1 zero-day exploits on a network.**

The initial set of invariants implemented in *EternalSafety* are supersets of
the specific violations utilized by the Eternal* exploits, and were selected
due to their potential for triggering SMB sever bugs like race conditions,
memory leaks, and buffer overruns. In future, it would be possible to implement
an even broader set of invariants encompassing more of the SMBv1 specification,
and even to expand this to SMBv2.

Installation
------------

This package can be installed through the Zeek package manager:

    zkg refresh
    zkg install lexibrent/zeek-EternalSafety


Usage
-----

This package outputs the following notices:

### EternalSafety::EternalBlue

### EternalSafety::EternalSynergy

### EternalSafety::EternalChampion

### EternalSafety::DoublePulsar

### EternalSafety::ViolationPidMid

### EternalSafety::ViolationCmd

### EternalSafety::ViolationTx2Cmd

### EternalSafety::ViolationNtRename


About
-----

Written by Lexi Brent [lexi.brent@sydney.edu.au](mailto:lexi.brent@sydney.edu.au)

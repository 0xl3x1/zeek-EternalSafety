zeek-EternalSafety
==================

*EternalSafety* is a Zeek/Bro package for detecting potentially-dangerous SMBv1
protocol violations that encapsulate bugs exploited by the infamous
[Eternal*](https://en.wikipedia.org/wiki/EternalBlue) family of Windows
exploits. It is capable of detecting EternalBlue,
EternalSynergy/EternalRomance, EternalChampion, and the DoublePulsar backdoor.
However, rather than identifying these exploits via simple signature-matching,
*EternalSafety* instead implements a set of SMBv1 protocol invariants that
encapsulate techniques used by each Eternal* exploit to trigger bugs in
unpatched Windows systems. 

*EternalSafety* accurately and reliably identifies the EternalBlue,
EternalSynergy and EternalRomance exploits, and the DoublePulsar backdoor
implant. Due to limitations in Zeek's SMBv1 support, it has limited support for
detecting EternalChampion via signature-matching. *EternalSafety* also
identifies a range of other protocol violations, such as the use of
unimplemented/unused SMBv1 commands, server-initiated changes in values that
may only be set by an SMBv1 client, incorrect interleaving of transaction
types, incorrect ordering of transaction messages, and sending more data as
part of a transaction than was specified in the transaction request.

Rationale
---------

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

Note that although the bugs exploited by the Eternal* exploits have been
patched *EternalSafety* still serves a clear purpose. A huge number of
unpatched machines remain in use in networks around the world, and this family
of exploits remains in widespread use by malicious actors and malware. It is
also still common for organizations to run older versions of Windows to support
legacy applications. Additionally, there may be other, as-of-yet undiscovered,
SMBv1 bugs in Windows systems, whose exploitation may be detected by
*EternalSafety*. 

Installation
------------

This package can be installed through the Zeek package manager:

    zkg refresh
    zkg install lexibrent/zeek-EternalSafety


Usage
-----

This package raises the following notices:

### EternalSafety::EternalBlue

Indication of a possible EternalBlue or other buffer exploit attempt by an
SMBv1 client. This notice is triggered if an SMBv1 client sends an
[SMB_COM_TRANSACTION2_SECONDARY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/80207e03-6cd6-4bbe-863f-db52f4d2cb1a)
request interleaved with an
[SMB_COM_NT_TRANSACT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/55db04d6-105f-45d1-84ac-6972c0a1ddc8)
transaction type.

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

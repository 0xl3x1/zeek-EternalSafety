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
patched, *EternalSafety* still serves a clear purpose. A huge number of
unpatched machines remain in use in networks around the world, and this family
of exploits remains [in widespread
use](https://www.sentinelone.com/blog/eternalblue-nsa-developed-exploit-just-wont-die/)
by malicious actors and
[malware](https://techcrunch.com/2019/05/12/wannacry-two-years-on/). It is also
still common for organizations to run older versions of Windows to support
legacy applications. Additionally, there may be other as-of-yet undiscovered
SMBv1 bugs in Windows systems, whose exploitation *EternalSafety* may be able
to detect.

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

Indication of dangerous behaviour and a possible EternalSynergy or
EternalRomance exploit attempt by an SMBv1 client. This notice is triggered if
an SMBv1 client sends an
[SMB_COM_WRITE_ANDX](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/81aec377-0ff4-4fc4-bc56-8f05b70c3e42)
command interleaved with the execution of *any* different transaction type.

Note that this is a superset of the specific violation caused by
EternalSynergy, which specifically interleaves
[SMB_COM_WRITE_ANDX](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/81aec377-0ff4-4fc4-bc56-8f05b70c3e42)
with an
[SMB_COM_TRANSACTION](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/0ed1ad9f-ab96-4a7a-b94a-0915f3796781)
and
[SMB_COM_TRANSACTION_SECONDARY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a4c64387-1dc4-45fb-b01f-9ad8b69e83e1).

### EternalSafety::EternalChampion

Indication of a possible EternalSynergy exploit attempt by an SMBv1 client.
This notice is triggered by a signature that matches a single packet containing
two SMB commands: an
[SMB_COM_NT_TRANSACT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/55db04d6-105f-45d1-84ac-6972c0a1ddc8)
with the unimplemented
[NT_TRANSACT_RENAME](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/95b5e728-7ff1-4e53-a9f2-66f031d86b4c)
subcommand, followed immediately by an
[SMB_COM_NT_TRANSACT_SECONDARY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/0941c749-cbf3-4c1b-91b2-b013a7473827)
command.

**NOTE:** due to limitations in Zeek's SMBv1 protocol support, this notice is
triggered by a signature, and hence may not trigger reliably (for instance, if
a matching packet is out of range of the region of the TCP stream that Zeek is
configured to match against).

See: https://msrc-blog.microsoft.com/2017/06/29/eternal-champion-exploit-analysis/

### EternalSafety::DoublePulsar

Indication of a possible DoublePulsar backdoor implant on an SMBv1 server.
This notice is triggered when an SMBv1 server changes the `MID` SMBv1 header
field value mid-transaction (a violation of the SMBv1 protocol specification),
AND the new value is in the range 81 <= `MID` < 84.

DoublePulsar uses the value of `MID` as a covert channel for receiving commands
and sending back status codes.

### EternalSafety::ViolationPidMid

Indication of a misbehaving, and possibly-compromised SMBv1 server. This notice
is a superset of EternalSafety::DoublePulsar, and is triggered whenever an
SMBv1 server introduces a new `MID` (multiplex identifier) or `PID` (process
identifier) value in the SMBv1 header. This is a violation of the SMBv1
protocol, and may indicate the use of a covert channel or some other buggy or
malicious misbehaviour.

### EternalSafety::ViolationCmd

Indication of a misbehaving, possibly malicious SMBv1 client. This notice is
triggered when an SBMv1 client sends a request containing any unused or
unimplemented primary SMB command. This is a violation of the SMBv1 protocol,
and could indicate an exploit attempt (e.g. trying to trigger a maliciously
injected command handler).

According to the SMBv1 protocol specification:

> If a code or code range is marked Unused, it is undefined and reserved for
> future use. If a code or code range is marked Reserved, it is or was reserved
> for a specific purpose. Both of these indicate that client implementations
> SHOULD NOT send messages using any of those command codes.

See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/32b5d4b7-d90b-483f-ad6a-003fd110f0ec

### EternalSafety::ViolationTx2Cmd

Indication of a misbehaving, possibly malicious SMBv1 client. This notice is
triggered when an SBMv1 client sends an
[SMB_COM_TRANSACTION2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/3d9d8f3e-dc70-410d-a3fc-6f4a881e8cab)
request containing any unimplemented transaction subcommand. This is
a violation of the SMBv1 protocol, and could indicate an exploit attempt (e.g.
trying to trigger a maliciously injected command handler).

According to the SMBv1 protocol specification, for each of the unimplemented
transaction subcommands:

> Clients SHOULD NOT send requests using this command code.

See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/14937ad8-38af-4c74-9604-ddb8470d0ed9

### EternalSafety::ViolationNtRename

Triggered by a signature that matches an
[SMB_COM_NT_TRANSACT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/55db04d6-105f-45d1-84ac-6972c0a1ddc8)
command with the unimplemented subcommand
[NT_TRANSACT_RENAME](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/95b5e728-7ff1-4e53-a9f2-66f031d86b4c).
This is a superset of the EternalSafety::EternalChampion notice.

**NOTE:** due to limitations in Zeek's SMBv1 protocol support, this notice is
triggered by a signature, and hence may not trigger reliably (for instance, if
a matching packet is out of range of the region of the TCP stream that Zeek is
configured to match against).

According to the SMBv1 specification for NT_TRANSACT_RENAME:

> Clients SHOULD NOT send requests using this subcommand code.

Hence, use of this subcommand is automatically suspicious and may indicate
a buggy client or malicious exploit attempt. This subcommand is used by several
exploits to trigger execution of a malicious injected event handler. See:
https://msrc-blog.microsoft.com/2017/06/29/eternal-champion-exploit-analysis/

About
-----

Written by Lexi Brent [lexi.brent@sydney.edu.au](mailto:lexi.brent@sydney.edu.au)

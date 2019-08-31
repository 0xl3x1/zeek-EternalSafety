module EternalSafety;
    
# Set to True to enable some debug prints
const DEBUG = T;

export {
    redef enum Notice::Type += {
        EternalBlue,     # => possible EternalBlue exploit
        DoublePulsar,    # => possible DoublePulsar backdoor
        ViolationPidMid, # => server introduced new PID or MID, a protocol 
                         #    violation and possible indication of 
                         #    compromise/backdoor covert channel
        ViolationCmd,    # => SMBv1 client sent unused/unimplemented command
        ViolationTx2Cmd, # => SMBv1 client sent unused TRANSACTION2 subcommand
        ViolationNtTxCmd,# => SMBv1 client sent unused NT_TRANSACT subcommand
    };

    # SMB transactions are uniquely identified by <pid, mid, tid, uid>
    type SMBTransID: record {
        pid: count; # Process ID
        mid: count; # Multiplex ID
        tid: count; # Tree ID
        uid: count; # User ID
    };

    type SMBStreamID: record {
        pid: count; # Process ID
        mid: count; # Multiplex ID
    };

    # Table to track SMBv1 transactions per connection
    # use a set here because for our TXn invariants we don't care about
    # command sequence
    type SMBTransTable: table[SMBTransID] of set[count];

    # Table to track streams per connection
    # use a vector because we do care about command sequence for
    # some of our stream-related invariants
    type SMBStreamTable: table[SMBStreamID] of vector of count;

    # Set of notice types
    type NoticeSet: set[Notice::Type];

    # Relevant SMBv1 commands
    const SMB_COM_NT_TRANSACT = 0xA0;
    const SMB_COM_TRANSACTION2 = 0x32;
    const SMB_COM_TRANSACTION2_SECONDARY = 0x33;
    const SMB_COM_LOCKING_ANDX = 0x24;

    # Unimplemented/reserved primary commands
    # See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/32b5d4b7-d90b-483f-ad6a-003fd110f0ec
    const SMB_COM_QUERY_SERVER        = 0x21;
    const SMB_COM_IOCTL_SECONDARY     = 0x28;
    const SMB_COM_NEW_FILE_SIZE       = 0x30;
    const SMB_COM_CLOSE_AND_TREE_DISC = 0x31;
    const SMB_COM_FIND_NOTIFY_CLOSE   = 0x35;
    const SMB_COM_READ_BULK           = 0xD8;
    const SMB_COM_WRITE_BULK          = 0xD9;
    const SMB_COM_WRITE_BULK_DATA     = 0xDA;

    const SMB_COM_UNUSED = {
        SMB_COM_QUERY_SERVER,
        SMB_COM_IOCTL_SECONDARY,
        SMB_COM_NEW_FILE_SIZE,
        SMB_COM_CLOSE_AND_TREE_DISC,
        SMB_COM_FIND_NOTIFY_CLOSE,
        SMB_COM_READ_BULK,
        SMB_COM_WRITE_BULK,
        SMB_COM_WRITE_BULK_DATA,

        # Unused command regions:
        # (From here:
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/32b5d4b7-d90b-483f-ad6a-003fd110f0ec)
        0x15, 0x16, 0x17, 0x18, 0x19,

        0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
        0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
        0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,

        0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d,

        0x7f,

        0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
        0x9b, 0x9c, 0x9d, 0x9e, 0x9f,

        0xA3,

        0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
        0xbc, 0xbd, 0xbe, 0xbf,

        0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
        0xcf,

        0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
        0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
        0xfc, 0xfd,
    };

    # Unimplemented TXn subcommands
    # See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/14937ad8-38af-4c74-9604-ddb8470d0ed9

    # for SMB_COM_TRANSACTION2:
    const TRANS2_SET_FS_INFORMATION       = 0x0004;
    const TRANS2_FSCTL                    = 0x0009;
    const TRANS2_IOCTL2                   = 0x000a;
    const TRANS2_SESSION_SETUP            = 0x000e;
    const TRANS2_REPORT_DFS_INCONSISTENCY = 0x0011;

    const TRANS2_UNUSED = {
        TRANS2_SET_FS_INFORMATION,
        TRANS2_FSCTL,
        TRANS2_IOCTL2,
        TRANS2_SESSION_SETUP,
        TRANS2_REPORT_DFS_INCONSISTENCY,
    };

    # for SMB_COM_NT_TRANSACT:
    const NT_TRANSACT_RENAME = 0x0005;
    
    const NT_TRANSACT_UNUSED = {
        NT_TRANSACT_RENAME,
    };

}

redef record connection += {
    # track SMBv1 transactions within the connection
    es_smb_trans: SMBTransTable &default=SMBTransTable();
    es_current_smb_trans: SMBTransID &optional;

    # track SMB connection streams
    es_smb_streams: SMBStreamTable &default=SMBStreamTable();
    es_current_smb_stream: SMBStreamID &optional;

    # track whether we have warned about each type of exploit, so we only warn
    # once per connection
    es_notices_issued: NoticeSet &default=NoticeSet();
};

event bro_init()
    {
    }

event connection_established(c: connection)
    {
    }

# Issues a new notice if such a notice hasn't already been issued for the
# current connection
function notice(c: connection, n: Notice::Info)
    {
    # Only issue the notice if it hasn't already been issued for this conn
    if (n$note !in c$es_notices_issued)
        {
        add c$es_notices_issued[n$note];
        if (DEBUG)
            {
            # add Wireshark-readable timestamp in debug mode
            # and print to stdout in addition to NOTICE()
            n$msg = fmt("t=%s: %s", network_time(), n$msg);
            print n$msg;
            }
        NOTICE(n);
        }
    }

# Track a new SMB command as part of the current SMB session
function seen_smb_command(c: connection, command: count)
    {
    # track transactions
    if (c$es_current_smb_trans !in c$es_smb_trans)
        c$es_smb_trans[c$es_current_smb_trans] = set(command);
    else 
        add c$es_smb_trans[c$es_current_smb_trans][command];

    # track the stream
    if (c$es_current_smb_stream !in c$es_smb_streams)
        c$es_smb_streams[c$es_current_smb_stream] = vector(command);
    else 
        c$es_smb_streams[c$es_current_smb_stream] += command;
    }

# Triggers if SMB client sends unimplemented/unused primary SMB command
function invariant_unused_smb_cmd(c: connection, hdr: SMB1::Header, 
                                  is_orig: bool)
    {
    # if this is a response from the server, just ignore it
    if (!is_orig)
        return;

    # else raise notice if this is a client->srv message with an unused command
    else if (hdr$command in SMB_COM_UNUSED)
            notice(c,[$note=ViolationCmd,
                      $msg=fmt("SMBv1 proto violation, possibly malicious " +
                               "activity: %s:%s sent unused/unimplemented " +
                               "command 0x%x to %s:%s",
                               c$id$orig_h, c$id$orig_p,
                               hdr$command,
                               c$id$resp_h, c$id$resp_p),
                      $conn=c]);
    }

# Server is not allowed to introduce a new MID into the stream.
# Only client can do this. DoublePulsar violates this invariant.
function invariant_new_pid_mid_from_server(c: connection, hdr: SMB1::Header,
                                           is_orig: bool)
    {
    # Client is allowed to vary these fields
    if (is_orig)
        return;

    # message is from server and is not preceeded by any corresponding message
    # from client, and this is the first message with this (pid, mid) combo
    if (|c$es_smb_streams[c$es_current_smb_stream]| == 1)
        {
        # These MID values in a Trans2 resp are usually used by DoublePulsar
        if (hdr$command == SMB_COM_TRANSACTION2 &&
              hdr$mid >= 81 && hdr$mid <= 83)
            notice(c,[$note=DoublePulsar,
                      $msg=fmt("Possible DoublePulsar backdoor detected on %s:%s",
                               c$id$resp_h, c$id$resp_p),
                      $conn=c]);
        # Any other invalid value => raise a more general notice
        else
            {
            # 0xFFFF is a valid value only for SMB_COM_LOCKING_ANDX
            # See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/9ab1f759-689d-481a-b160-b8f0eb09f5fb
            if (hdr$command == SMB_COM_LOCKING_ANDX && hdr$mid == 0xFFFF)
                return;

            # All other cases are now a violation...
            notice(c, [$note=ViolationPidMid,
                       $msg=fmt("Possible compromised SMBv1 server %s:%s " +
                                "(srv sent new PID/MID - protocol violation)", 
                                c$id$resp_h, c$id$resp_p),
                       $conn=c]);
            }
        }
    }

# Note: this gets executed before the other smb1_* events
# NOTE: if is_orig == T, then the message is a request. Else, it is a resp.
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
    {
    local current_trans: SMBTransID = [
        $pid = hdr$pid,
        $mid = hdr$mid,
        $tid = hdr$tid,
        $uid = hdr$uid
    ];

    local current_stream: SMBStreamID = [
        $pid = hdr$pid,
        $mid = hdr$mid
    ];

    c$es_current_smb_trans = current_trans;
    c$es_current_smb_stream = current_stream;

    seen_smb_command(c, hdr$command);

    # check that invariants hold
    # these functions raise notices as appropriate for violations
    invariant_new_pid_mid_from_server(c, hdr, is_orig);
    invariant_unused_smb_cmd(c, hdr, is_orig);
    }

# Produces a notice if an unused/unimplemented TRANS2 sub-command is seen
function invariant_unused_trans2_subcmd(c: connection, trans2_sub_cmd: count)
    {
    if (trans2_sub_cmd in TRANS2_UNUSED)
        notice(c,[$note=ViolationCmd,
                  $msg=fmt("SMBv1 proto violation, possibly malicious " +
                           "activity: %s:%s sent unused/unimplemented " +
                           "TRANSACTION2 subcommand 0x%04x to %s:%s",
                           c$id$orig_h, c$id$orig_p,
                           trans2_sub_cmd,
                           c$id$resp_h, c$id$resp_p),
                  $conn=c]);
    }

# Trans2 Request (0x32) MS-2.2.4.46.1
event smb1_transaction2_request(c: connection, hdr: SMB1::Header, 
                                args: SMB1::Trans2_Args, sub_cmd: count)
    {
    invariant_unused_trans2_subcmd(c, sub_cmd);
    }

# Trans2 Secondary Request (0x33) MS:2.2.4.47.1
event smb1_transaction2_secondary_request(c: connection, hdr: SMB1::Header,
                                          args: SMB1::Trans2_Sec_Args, 
                                          parameters: string, data: string)
    {
    # SMB protocol violation used by EternalBlue:
    # NT_TRANSACT and TRANSACTION2 transaction types must NOT be interleaved.
    if (SMB_COM_NT_TRANSACT in c$es_smb_trans[c$es_current_smb_trans])
            notice(c, [$note=EternalBlue,
                       $msg=fmt("SMBv1 proto violation, possible " +
                                "EternalBlue or other buffer exploit: " +
                                "%s:%s tried to interleave NT_TRANSACT " +
                                "and TRANS2 commands in request to %s:%s",
                                c$id$orig_h, c$id$orig_p,
                                c$id$resp_h, c$id$resp_p),
                       $conn=c]);
    }

event bro_done()
    {
    }

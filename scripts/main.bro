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
    };

    # SMB transactions are uniquely identified by <pid, mid, tid, uid>
    type SMBTransID: record {
        pid: count; # Process ID
        mid: count; # Multiplex ID
        # tid: count; # Tree ID
        # uid: count; # User ID
    };

    # Table to track SMBv1 transactions per connection
    type SMBTransTable: table[SMBTransID] of vector of count;

    # Set of notice types
    type NoticeSet: set[Notice::Type];

    # Relevant SMBv1 commands
    const SMB_COM_NT_TRANSACT = 0xA0;
    const SMB_COM_TRANSACTION2 = 0x32;
    const SMB_COM_TRANSACTION2_SECONDARY = 0x33;
    const SMB_COM_LOCKING_ANDX = 0x24;
}

redef record connection += {
    # track current SMBv1 transaction parameters
    es_smb_trans: SMBTransTable &default=SMBTransTable();

    # track all seen SMBv1 transaction parameters
    es_current_smb_trans: SMBTransID &optional;

    # track whether we have warned about each type of exploit, so we only warn
    # once per connection
    es_notices_issued: NoticeSet &default=NoticeSet();
};

global first_time: time = 0;

event bro_init()
    {
    }

event connection_established(c: connection)
    {
    if (first_time == 0)
        first_time = c$start_time;
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
            n$msg = fmt("t=%s: %s", 
                        interval_to_double(network_time()-first_time), n$msg);
            print n$msg;
            }
        NOTICE(n);
        }
    }

# Track a new SMB command as part of the current SMB session
function seen_smb_command(c: connection, command: count)
    {
        if (c$es_current_smb_trans !in c$es_smb_trans)
            c$es_smb_trans[c$es_current_smb_trans] = vector(command);
        else 
            c$es_smb_trans[c$es_current_smb_trans] += command;
    }

# Server is not allowed to introduce a new MID into the stream.
# Only client can do this. DoublePulsar violates this invariant.
function invariant_new_pid_mid_from_server(c: connection, hdr: SMB1::Header, is_orig: bool)
    {
    # Client is allowed to vary these fields
    if (is_orig)
        return;

    # message is from server and is not preceeded by any corresponding message
    # from client, and this is the first message with this (pid, mid) combo
    if (|c$es_smb_trans[c$es_current_smb_trans]| == 1)
        {
        # These MID values in a Trans2 resp are usually used by DoublePulsar
        if (hdr$command == SMB_COM_TRANSACTION2 && hdr$mid >= 81 && hdr$mid <= 83)
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
            $mid = hdr$mid
        ];

        c$es_current_smb_trans = current_trans;

        seen_smb_command(c, hdr$command);

        invariant_new_pid_mid_from_server(c, hdr, is_orig);

        # TODO: warn on use of any unimplemented commands
        # see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/32b5d4b7-d90b-483f-ad6a-003fd110f0ec
        # and https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/14937ad8-38af-4c74-9604-ddb8470d0ed9
        # these can be used as malware entry points
    }

# Trans2 Request (0x32) MS-2.2.4.46.1
event smb1_transaction2_request(c: connection, hdr: SMB1::Header, args: SMB1::Trans2_Args, sub_cmd: count)
    {
    }

# Trans2 Secondary Request (0x33) MS:2.2.4.47.1
event smb1_transaction2_secondary_request(c: connection, hdr: SMB1::Header, args: SMB1::Trans2_Sec_Args, parameters: string, data: string)
    {
    # SMB protocol violation used by EternalBlue:
    # A transaction initiated with NT_TRANSACT must not receive
    # TRANSACTION2_* requests.
    if (SMB_COM_NT_TRANSACT in c$es_smb_trans[c$es_current_smb_trans])
            notice(c, [$note=EternalBlue,
                       $msg="Possible EternalBlue/SMBv1 buffer exploit detected",
                       $conn=c]);
    }

event bro_done()
    {
    }

module EternalBlue;
    
export {
    redef enum Notice::Type += {
        EternalBlue,  # => possible EternalBlue exploit
        DoublePulsar, # => possible DoublePulsar backdoor
    };

    # SMB transactions are uniquely identified by <pid, mid, tid, uid>
    type SMBTransID: record {
        pid: count;
        mid: count;
        tid: count;
        uid: count;
    };

    # Table to track SMBv1 transactions per connection
    type SMBTransTable: table[SMBTransID] of set[count];

    # Relevant SMBv1 commands
    const SMB_COM_NT_TRANSACT = 0xA0;
    const SMB_COM_TRANSACTION2 = 0x32;
    const SMB_COM_TRANSACTION2_SECONDARY = 0x33;
}


redef record connection += {
    # track current SMBv1 transaction parameters
    smb_trans: SMBTransTable &optional;
    # track all seen SMBv1 transaction parameters
    current_smb_trans: SMBTransID &optional;
    # track whether we have warned about each type of exploit, so we only warn
    # once per connection
    eternal_blue_notice: bool &default=F;
    double_pulsar_notice: bool &default=F;
};

event bro_init()
    {
    }

event connection_established(c: connection)
    {
    c$smb_trans = SMBTransTable();
    }

# Track a new SMB command as part of the current SMB session
function add_seen_smb_command(c: connection, command: count)
    {
        if (c$current_smb_trans !in c$smb_trans)
            c$smb_trans[c$current_smb_trans] = set(command);
        else 
            add c$smb_trans[c$current_smb_trans][command];
    }

# Note: this gets executed before the other smb1_* events
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
    {
        local current_trans: SMBTransID = [
            $pid = hdr$pid,
            $mid = hdr$mid,
            $tid = hdr$tid,
            $uid = hdr$uid
        ];

        c$current_smb_trans = current_trans;

        add_seen_smb_command(c, hdr$command);

        # print fmt("smb1_message: %2x", hdr$command);

        # NT Trans Request (0xA0) MS-2.2.4.62.1
        if (hdr$command == SMB_COM_TRANSACTION2)
            {
            # TODO: enhance this to check for MID(resp) != MID(req)
            # Primitive check for DoublePulsar backdoor
            if (hdr$mid >= 81 && hdr$mid <= 83)
                {
                if (!c$double_pulsar_notice)
                    {
                    print "Possible DoublePulsar backdoor";
                    NOTICE([$note=DoublePulsar,
                            $msg="Possible DoublePulsar backdoor detected",
                            $conn=c]);
                    c$double_pulsar_notice = T;
                    }
                }
            }

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
    if (SMB_COM_NT_TRANSACT in c$smb_trans[c$current_smb_trans])
        {
        if (!c$eternal_blue_notice)
            {
            print "Possible EternalBlue/SMBv1 buffer exploit";
            NOTICE([$note=EternalBlue,
                    $msg="Possible EternalBlue/SMBv1 buffer exploit detected",
                    $conn=c]);
            c$eternal_blue_notice = T;
            }
        }
    }

event bro_done()
    {
    }

module EternalBlue;

export {
    redef enum Log::ID += { LOG };

    redef enum Notice::Type += {
        EternalBlue,
        DoublePulsar,
    };

    type : record {
        ts: time &log;
        id: conn_id &log;
        smb_hdr: SMB1::Header &log;
        msg: string &log;
    };

    # SMB transactions are identified by <pid, mid, tid, uid>
    type SMBTransID: record {
        pid: count;
        mid: count;
        tid: count;
        uid: count;
        # trans: bool &default = F;
        # trans2: bool &default = F;
    };

    type SMBTransTable: table[SMBTransID] of set[count];

    const SMB_COM_NT_TRANSACT = 0xA0;
    const SMB_COM_TRANSACTION2 = 0x32;
    const SMB_COM_TRANSACTION2_SECONDARY = 0x33;
}


redef record connection += {
    eternalblue: Info &optional;
    smb_trans: SMBTransTable &optional;
    current_smb_trans: EternalBlue::SMBTransID &optional;
};

event bro_init()
    {
    Log::create_stream(EternalBlue::LOG, [$columns=Info, $path="EternalBlue"]);
    }

event connection_established(c: connection)
    {
    local rec: EternalBlue::Info = [
        $ts = network_time(),
        $id = c$id
    ];
    c$eternalblue = rec;

    c$smb_trans = table();

    # Log::write(EternalBlue::LOG, rec);
    }

function add_seen_smb_command(c: connection, command: count)
    {
        if (c$current_smb_trans !in c$smb_trans) {
            c$smb_trans[c$current_smb_trans] = set(command);
        } else {
            add c$smb_trans[c$current_smb_trans][command];
        }
    }

# Note: this gets executed before the other smb1_* events
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
    {
        local current_trans: EternalBlue::SMBTransID = [
            $pid = hdr$pid,
            $mid = hdr$mid,
            $tid = hdr$tid,
            $uid = hdr$uid
        ];

        c$current_smb_trans = current_trans;

        # print fmt("smb1_message: %2x", hdr$command);

        # NT Trans Request (0xA0) MS-2.2.4.62.1
        if (hdr$command == SMB_COM_NT_TRANSACT) {
            add_seen_smb_command(c, SMB_COM_NT_TRANSACT);
        } else if (hdr$command == SMB_COM_TRANSACTION2) {
            # TODO: enhance this to check for MID(resp) != MID(req)
            # Primitive check for DoublePulsar backdoor
            if (hdr$mid >= 81 && hdr$mid <= 83) {
                print "POSSIBLE DoublePulsar BACKDOOR";
            }
        }
    }

# Trans2 Request (0x32) MS-2.2.4.46.1
event smb1_transaction2_request(c: connection, hdr: SMB1::Header, args: SMB1::Trans2_Args, sub_cmd: count)
    {
    add_seen_smb_command(c, SMB_COM_TRANSACTION2);
    }

# Trans2 Secondary Request (0x33) MS:2.2.4.47.1
event smb1_transaction2_secondary_request(c: connection, hdr: SMB1::Header, args: SMB1::Trans2_Sec_Args, parameters: string, data: string)
    {
    if (SMB_COM_NT_TRANSACT in c$smb_trans[c$current_smb_trans]) {
        print "SMB PROTOCOL VIOLATION";
    }
    }

event bro_done()
    {
    }

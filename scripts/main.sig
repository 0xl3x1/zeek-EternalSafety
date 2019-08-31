# Matches a packet with an SMB_COM_NT_TRANSACT with subcommand NT_RENAME
signature smb-nt-transact-rename {
    ip-proto == ip
    tcp-state originator
    payload /.*[\xFF]SMB[\xA0].{28}.{4}.{24}.{4}.{5}[\x05\x00]/
    event "originator sent NT_TRANSACT NT_RENAME"
}

# This will not work all the time because of regexp matching being limited to
# a pre-defined buffer. However, it *will* always work for the NSA's particular
# EternalChampion exploit, since that exploit always sends the same payload.
# There is no better way to implement this yet, since Bro's SMBv1 support is
# missing events for the SMB_COM_NT_TRANSACT* commands.
signature smb-nt-transact-rename-secondary {
    ip-proto == ip
    tcp-state originator
    payload /.*[\xFF]SMB[\xA0].{28}.{4}.{24}.{4}.{5}[\x05\x00].*[\xFF]SMB[\xA1]/
    event "possible EternalChampion race condition exploit"
}

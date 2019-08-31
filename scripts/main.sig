# Matches a packet with an SMB_COM_NT_TRANSACT with subcommand NT_RENAME
signature smb-nt-transact-rename {
    ip-proto == ip
    tcp-state originator
    payload /.*[\xFF]SMB[\xA0].{28}.{4}.{24}.{4}.{5}[\x05\x00]/
    event "originator sent NT_TRANSACT NT_RENAME"
}

signature smb-nt-transact-rename-secondary {
    ip-proto == ip
    tcp-state originator
    payload /.*[\xFF]SMB[\xA0].{28}.{4}.{24}.{4}.{5}[\x05\x00].*[\xFF]SMB[\xA1]/
    event "possible EternalChampion race condition exploit"
}

Shadowbrokers PCAPs. etc.

Eric Conrad
Twitter: @eric_conrad
econrad at gmail dot com
http://ericconrad.com

Current PCAPs:

 - eternalromance-success-2008r2.pcap
   - Successful eternalromance exploit vs 2008r2

 - eternalromance-doublepulsar-meterpreter.pcap
   - Installs DoublePulsar via EternalRomance
   - Then injects Metasploit x64 meterpreter DLL via DoublePulsar
   - Victim system then connects to reverse meterpreter handler
 
 - eternalblue-success-unpatched-win7.pcap 
   - Successful EternalBlue attack vs win7
   - Wireshark display filter "smb.mid == 65" looks promising

 - eternalblue-failed-patched-win7.pcap
   - Failed EternaBlue attack vs win7 patched this morning (April 16th)

 - doublepulsar-backdoor-connect-win7.pcap 
   - Connect to existing EternalBlue-installed DoublePulsar backdoor
   - Wireshark display filter "smb.mid == 81" appears to catch this

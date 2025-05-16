#TRUSTED 7b63cb2fc177dd5e77c53a556a7305f351821a68ca682b2ac8ae3f8cd31d05126db7dbdbc603e8257ff2f7850d083a26422bc3480c2f689d7147f0a06ac53def9121056e7f1716cd8ae3c6afbe249acf9c96d199f2ce635e8a22aeef24ad5d7f0e825f369027a84a06130e668c25c19b232a56c0e065425b09fbc82fefb6fbb089c6fb146206fff0d13cf6cfa0bb94ebd8a3995cb815c31cce9b58e6b3af20ee49451495e010af4c5128a89871d8d2935202e1042881174824b054944e3c47ca38c679527bcea45ebb3915709b3d8e8a63772e5c69cacdfc10c90b8dc7959e7d9081bcf7f25b091201955744b3e6b296acf02bff42749f4fe664e0fe3edf31bacafab6904d1e5d60be617b57f05f2a03781fca9ac315658642d98b6cdf87a7dbcd7165abbd8b29c1fe0f8ea7910c939e873b79b574c80f4ab10af347c2a176c62554480032ccdc7183a2a6cff0b419fd1d2736d7d4da104a672b7ed026d70e77b65a28ebd54b788266cac0417c43c5791d18ea868450906de62c9e3e648d982e8e0c534ee06980455533abd01818029a527ed076dc7e0f81e9f1b46c27f2b2356c602cc262d4bdde523831eff36557ecf8778f4341d787efcf20e7e96540b9203fb65fd79150a8ce102a8785438f8133daeb2f09f5f02372b7e50c16be66673124353e9d92cd4746367fe0da1ce7c86a81e82b8beb1f0c575ce7520a3f5eb4fc
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.1
#

include("compat_shared.inc");
include("byte_func.inc");

##
# Establishes an RMI connection with the server. Upon
# success a new socket is returned. Audit is called if
# we are unable to connect or the protocol doesn't look
# right.
## 
function rmi_connect(port,ssl)
{
	local_var soc;

  soc = open_sock_tcp(port);
	if (!soc) audit(AUDIT_NOT_LISTEN, "RMI", port);

  if(ssl && get_port_transport(port) == ENCAPS_IP)
  {
    soc = socket_negotiate_ssl(socket:soc, transport: ENCAPS_SSLv23 | ENCAPS_DISABLE_SSLv2 | ENCAPS_DISABLE_SSLv3);
    if(! soc) audit(AUDIT_FN_FAIL, "socket_negotiate_ssl");
  }
  

	# Try to open an RMIv2 stream protocol (0x4b) connection.
	local_var request = 'JRMI\x00\x02\x4b'; 
	send(socket:soc, data:request);

	# Do a quick check to see if the response indicates RMI
	local_var res = recv(socket:soc, length:64, min:7);
	if (isnull(res) || strlen(res) < 7 ||
	  getbyte(blob:res, pos:0) != 0x4e ||
	  (getword(blob:res, pos:1) + 7) != strlen(res))
	{
	  close(soc);
	  audit(AUDIT_RESP_BAD, port);
	}

	return soc;
}

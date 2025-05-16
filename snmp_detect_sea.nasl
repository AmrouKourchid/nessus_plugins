#TRUSTED 2ad76286198a501ffa9533c4b39cb33b8faf9cb7e802e6ac46835291e18e54337227417a541332e45f1e11f30cd8230c79ed64f12dc404aaddf1aa732f085d9059b8852b1d9062626525b1787d27db16e24c38c9da8a205cfa40228b60f6c1b29ee923edfe261f502e0ea4894f0dff6ac871c6e28af30b6af556a72c22b65d596a5340c77521b75cf8ff1be104be954347e3f7e502421d7a1dc74a3cefc2750be94256c3479ab8f03ee8fa59fc14beda128f059f243465b5635b3d2c82a04fd0d3930fdefb7eb4b8168f1f48bee23db74c54423216942d44c3594f3ff14c615af6e81b9c6fc2e06381899d45a8667567c66a49221c24a8c476f9f189ecbea54dc0b7ac0fff41005531ff545794b54607b0623b0e28a7da185a2dc392f188503ba68639ca3de5892b8045e8965354ceee462ceb66ea0aa35fbdd98be8d5e88023f26c8abb93009c1b333e7b40bee570c5a5909a900ead5a7ffb3ebba8b0e7ef81636f61ee3b43ee1eac6400cda52fffe9291f2a8fab91a3694baa9bae769dc5ac0b38b9e77251e9e412d718c59c75750f76329a6b89b59a6cbd326e767b81aa3fb64801f93e7f7aad0030f9f53aa23ee0d3f3f15849be8f47ea1101efcc570660806454bd77a97231506899fb6835215d924c3a21c159f31b9085f9203a83b53987039fca9f15cb2235639725ab2f27a6aaad6c25d0f94d3ff7d66036d05449e1
#TRUST-RSA-SHA256 35348243de6202047d3165be84922d512b6fc70fa56ccd7a8e61b8045d6fee51a1a157e4faf1292d78a45f6c22f06a05ac84f1b603b600e52533262f43884e4da5583a425b57a6876c340c76873d292e9d005420acf322befdffbc288a1e1093ca88d8ffa386b5fe7284b36c77617df6a45e85143a37c3c230d47d2c634d3dec19653e3cea40c6016489458f42baa74232a17c5d2d7cde9a1f882cad5f23ee96d53d58f72ea6cdd89e06e3f9cb1b6761384726badabc36c388581c21baec18d2ff7cd186d86dc8d53ec2d3139e6e471f5d76eae4c21d3b08e90dbe07792f02e156570715eb6fab688695fcf6068a267fc3032f8179b414d3ba63a1daf9f137cfe12925bdf4da6d17891b8df2bc5b20bd0c78c1f9d82189f645ccc88b8911a79000a763419903087ae4615547af0b43971ed80d76c930d1b93ae8677fb57286629e3c08eb19ce918cf09f24d006bda81dbf6713774a96af585a8b0456b14997132304ac5fad1c6ad6a0904ec965148f66b010b2802ffbe67989bfc67c370f4bbd87a0041619951c43db6b1ee3bd035f9538f003f02c413635847ee0165196c2168f2e28ee702d87d9c68d867f82f64637582800586f700f87a3613562b4ea25efd0e44243f3621eb381939c15f2445ebb09fefdb2b9e99b61b4855e4693f11c35a88d881b20f123309d13ca4dc2caa4103380d0913831933c04fed042a89502f6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56009);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_name(english:"Solstice Enterprise Agent SNMP (snmpdx) Detection");
  script_summary(english:"Checks for Solstice Enterprise Agent SNMP");

  script_set_attribute(attribute:"synopsis", value:
"An SNMP-based configuration utility was discovered on the remote
port.");
  script_set_attribute(attribute:"description", value:
"Solstice Enterprise Agent (SNMP), an agent-management utility from
Oracle, was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://docs.oracle.com/cd/E19455-01/806-2905/806-2905.pdf");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

  script_require_udp_ports(16161);
  script_dependencies("snmp_settings.nasl");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");


# These are most of the OIDs available, found using the documentation and
# a snmpwalk. We aren't actually using them, but I'm leaving them here
# as a reminder. These can be found in /var/snmp/mib/snmpdx.mib, but not
# in such a clean way.
oids = make_array(
  "1.3.6.1.4.1.42.2.15.1.0",  "sunMasterAgentStatusFile",
  "1.3.6.1.4.1.42.2.15.2.0",  "sunMasterAgentResourceConfigFile",
  "1.3.6.1.4.1.42.2.15.3.0",  "sunMasterAgentConfigurationDir",
  "1.3.6.1.4.1.42.2.15.4.0",  "sunMasterAgentTrapPort",
  "1.3.6.1.4.1.42.2.15.5.0",  "sunCheckSubAgentName",
  "1.3.6.1.4.1.42.2.15.6.0",  "sunMasterAgentPollInterval",
  "1.3.6.1.4.1.42.2.15.7.0",  "sunMasterAgentMaxAgentTimeOut",
  "1.3.6.1.4.1.42.2.15.8.0",  "sunSubAgentTable", # Not accessible - list of SunSubAgentEntry
  "1.3.6.1.4.1.42.2.15.9.0",  "sunSubAgentTableIndex",
  "1.3.6.1.4.1.42.2.15.10.0", "sunSubTreeConfigurationTable", # Not accessible - list of SunSubTreeConfigurationEntry
  "1.3.6.1.4.1.42.2.15.11.0", "sunSubTreeConfigurationTableIndex",
  "1.3.6.1.4.1.42.2.15.12.0", "sunSubTreeDispatchTable", # Not accessible - list of SunSubTreeDispatchEntry
  "1.3.6.1.4.1.42.2.15.13.0", "sunSubTreeDispatchTableIndex",

  "1.3.6.1.4.1.42.2.15.8.1.1",  "sunSubAgentID",
  "1.3.6.1.4.1.42.2.15.8.1.2",  "sunSubAgentStatus",
  "1.3.6.1.4.1.42.2.15.8.1.3",  "sunSubAgentTimeout",
  "1.3.6.1.4.1.42.2.15.8.1.4",  "sunSubAgentPortNumber",
  "1.3.6.1.4.1.42.2.15.8.1.5",  "sunSubAgentRegistrationFile",
  "1.3.6.1.4.1.42.2.15.8.1.6",  "sunSubAgentAccessControlFile",
  "1.3.6.1.4.1.42.2.15.8.1.7",  "sunSubAgentExecutable",
  "1.3.6.1.4.1.42.2.15.8.1.8",  "sunSubAgentVersionNum",
  "1.3.6.1.4.1.42.2.15.8.1.9",  "sunSubAgentProcessID",
  "1.3.6.1.4.1.42.2.15.8.1.10", "sunSubAgentName",
  "1.3.6.1.4.1.42.2.15.8.1.11", "sunSubAgentSystemUpTime",
  "1.3.6.1.4.1.42.2.15.8.1.12", "sunSubAgentEntry"
);

port = 16161;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

# Get the global community string for snmp
community = get_kb_item("SNMP/community");
if(!community)
  community = "public";

s = open_sock_udp(port, community);
if (!s) audit(AUDIT_SOCK_FAIL, port, "UDP");

# Get the important OIDs
status_file   = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.1.0"); # sunMasterAgentStatusFile
config_file   = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.2.0"); # sunMasterAgentResourceConfigFile
config_dir    = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.3.0"); # sunMasterAgentConfigurationDir
trap_port     = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.4.0"); # sunMasterAgentTrapPort
poll_interval = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.6.0"); # sunMasterAgentPollInterval
agent_timeout = snmp_request(socket:s, community:community, oid:"1.3.6.1.4.1.42.2.15.7.0"); # sunMasterAgentMaxAgentTimeOut
close(s);


# Check if the OID was present
if(!isnull(status_file))
{
  register_service(port:port, ipproto:"udp", proto:"solaris-sea-snmp");

  if(report_verbosity > 0)
  {
    extra = 'The Solstice Enterprise Agent has the following properties :' +
      '\n' +
      '\n  Status file             : ' + status_file +
      '\n  Resource config file    : ' + config_file +
      '\n  Configuration directory : ' + config_dir +
      '\n  SNMP Trap port          : ' + trap_port +
      '\n  Poll interval           : ' + poll_interval +
      '\n  Agent timeout           : ' + agent_timeout +
      '\n';

    security_note(port:port, proto:"udp", extra:extra);
  }
  else
  {
    security_note(port:port, proto:"udp");
  }
}

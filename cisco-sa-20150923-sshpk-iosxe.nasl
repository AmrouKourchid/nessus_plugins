#TRUSTED a0ce1991d12509094586ac281231e35fa8b0adc59f2dd6a357cdd6ddf7c239177cb3b5b00bc75557401e7cbc8e78d0bd106165eb4bb3962d6197d70c2bcafb0ac13fc8959dab2a9ef8a9ce4ec9a57110b537b0f205a46afff6b17bbaae3c6ab78e23bc5ee992513d5bf7503479fb06ee2c3086b1ef986016d217c8be401564278040bfbe6affd71a04a60f9f29e980b2fc6d7a7bf615a14f06a3dfe448ac119c71d3981f89a6b6125b081e8c3e6a4c11976f7fd87036804126e2edb8b9652fea252b3ad6915b07d62ec13f9f8d3a1b31ab06c900073ce6b25ba11b2e0f6008f32e4547edce381ef2942384b0036b69eb8ef5545d078dff4d01d1d19a0209f77acbeec7b8079d8b9ec599932b899ac5a83245aa2941c161b7f1bbdcd57ad24b75ac7e24e0259a680c7e4bd8b5861a8771e44c9328d7c8f5dae6c1cd4aa87df38ad85c8f4a8978352cf511c6a5f751aff390d6a34372e8df7d870947a3c96762b8b8477a9314ef07f7e8d6621c8d3e522e989bc4eabccf13f67f533322b416f9275c690dcee7baa812543e0d97a905f283a8e92679527f440e858864c0686881966cdb2b05cf508c2d5bc63ba845411edaa6ed70f58ed95159c5a68f1d808d53339e6bea41daf0a9048cbbeaf24497cde93563278c8d80f189e035648e20adb667a4661c13c27bc7399600e19475cdb414a264c7d66137d750c934a56516a84618
#TRUST-RSA-SHA256 1d66ee2cf965cebaa53cfed00889fd397c26226088a68caefe0310a40d1ccb457ffd90daffc07f71096cb98f225375ed896d9f3341dfc2a431884878151802fe3b7b14f0ce6404f7ed32754f98088342da332a81f5878fa929e358f1a990bf1a29ca09a0fa52c1cb27b79477a16a270a5400744c2e7f1d08ad292c219a7c5705f782486886e925025402ca8e6dba1622aac960e2e8c8e5347681ac288c3edbe84da997cd399d992a326b14851d936e977598a7f115aef48e86cb57fbb3fecfb84efd4f3c237b70b47784c762a3c469d9846c354f3d04e897cfe96e1d1ead09eac4292a75647ed06648a9cba3b928c55d185d66ed8a2f119a7700e41fb6a7d704556620a0a34dbdb18b658917ffd37de7e8c9234b586378536f7bda6d6849f7167700d92d9981b9e28bf287f21e9f4f4c28124b751ff8621354b80cb21d98030eac6833605457994a215e839f4d5de043cc5cbd39985ff941c695bd066bd3b1c96e9b6e98b01e1918ead1a56734249a2aab9dc750922fa345ec18490611695c0a2b672ef26499de11fa469fb1916221e91298f7b55f6a3ce55e1e971ce30cebcc7049de95a8eb42983ecec9b76bd24d148d468946dc3a6b68f634374e797a8f8d34c188b43358c32708152e6dd16ee980e589ac1bd0f102c2b4a137dfc6432f1da34f2dea6736fa6d258a60b51943da29d198de0972cb467cad3e5a7bff2ec391
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86250);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-6280");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus73013");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-sshpk");

  script_name(english:"Cisco IOS XE SSHv2 RSA-Based User Authentication Bypass (CSCus73013)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and is configured for SSHv2 RSA-based user authentication. It
is, therefore, affected by a flaw in the SSHv2 protocol implementation
of the public key authentication method. An unauthenticated, remote
attacker can exploit this, via a crafted private key, to bypass
authentication mechanisms. In order to exploit this vulnerability an
attacker must know a valid username configured for RSA-based user
authentication and the public key configured for that user.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-sshpk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2660861");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus73013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag     = 0;
override = FALSE;

if (version =='3.6.0E') flag++;
if (version =='3.6.0aE') flag++;
if (version =='3.6.0bE') flag++;
if (version =='3.6.1E') flag++;
if (version =='3.6.2E') flag++;
if (version =='3.6.2aE') flag++;
if (version =='3.7.0E') flag++;
if (version =='3.10.0S') flag++;
if (version =='3.10.01S') flag++;
if (version =='3.10.0aS') flag++;
if (version =='3.10.1S') flag++;
if (version =='3.10.2S') flag++;
if (version =='3.10.3S') flag++;
if (version =='3.10.4S') flag++;
if (version =='3.10.5S') flag++;
if (version =='3.11.0S') flag++;
if (version =='3.11.1S') flag++;
if (version =='3.11.2S') flag++;
if (version =='3.11.3S') flag++;
if (version =='3.12.0S') flag++;
if (version =='3.12.1S') flag++;
if (version =='3.12.2S') flag++;
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE software", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-begin-ip-ssh-pubkey-chain", "show running-config | begin ip ssh pubkey-chain");
  if (check_cisco_result(buf))
  {
    if (
      "ip ssh pubkey-chain" >< buf &&
      "username" >< buf
    )
      flag = 1;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCus73013' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));

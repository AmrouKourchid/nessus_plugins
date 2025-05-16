#TRUSTED 05e18b4a602a1c3a4e00efc30bb28e7f90a87998287736a15327a3a0fa801a4ded6bab8110b12e40dac22030122b203824a85f7de8427be4539dee01ae64b48d4a26d766984ad07f2169661527272c922eff9441563b93e9d264a7f531bc270655cf145205d043eb55519a1743ef95f0d9ac0b1caa2bd801a712f4d19f79806cd05bb49aaddf5459f609a8738ecf95a30ee8140ceab38feef10e7a38dfdd61a1fd45e740465955bbee22f549b1dbc679e68f487f5f8360142763e8491d61e4d0914835e07f5ff9edd6a4733916bac861c07b1e2a627f14ee6a84f44f42af98df4a946fe73471f6bae322e29cfc9ff96e8e1504f57d6cecce1c84b9ffee97688bf07e03c732fea6dfbcf7919a1a31b45f5a004d8c26453b19869b24d18b2073f7ed2348658ee5720e5eadd99e3cebb0e3c5443f93012786888569b9d1bc5e142b73d5b9635347b07a456d7244c674e3f57563aab4d6469a4cd8a40fa720cb2f591cf26dba23dc6755644db9e09e793ae37770a4b515bc02f1dd3da60c6eb2e0fdac2f336e60885fbba3a14a11d3b07032a5ae910f52073e145266e587662cdd7ce4351baf7ad35c8bfa2a5a38560e2d678dc8b5b4a2689d56494a11163cf9ddd1e281492da2cf29b34fa26a10c81b8ac6f7bb40822a01e3f15f90d8774abd624a07ab335617ee237045cf32391c15904aa6aa955a669c0cf7ae47c763418ad3bc
#TRUST-RSA-SHA256 40b825bc7ef72fad0f2c639fdfd548e5890862f6be51618e9e44fcb02df73ab6584562b785571e118f04c6dd8f2c13b01620f273c6c27125c9d004c593e819f84120feeb03d237256f51a5a68002f710e31029c474850f886e7de490808464d69831beed273e91426f9831a4bf2affa60bebc37720286272b940b5bc6d570353ccf9517051a9783bd480f8b43b3a5aa5171c4b956ed4829c5afd32e1d3e69b21879011377bc82b1391854587822db073c7edc64861e68349ca8ecbc72753b71735bb314b92e36beb07e9199f60be3da751b27545d678c760d7b795d2de36a82c8b08d8c5a09bf2400fb506415e80b7e077facbf537231e355500c269c05c0f2c9ca5fe7a1f97123fbbb3539fa5591dc2ff65556c79a8b684cd76d919a2504b4908388856b9152d7f01726696459bc2d52147b3acf2bef1d2534da4eb7089919d760be731f2808809b187c0cd6ea2b5b51d708870b30ca65f4632527971737ec158bcea9e667f2ea2a8f016a96231555c234f889f7352db22b0d457ba138e3ececcb164c885491cee907bc012945d289255650787b478e900e12e19f3ccf5a666f90c31d1485af41233483d0083f20cf132251e556587d41b4bcd2cd49c6baf6ff1ebd7fc374c2774a440d980225807ac1dec1088179f12ac89d811ab0f81d1e9e741360d981bc8d125b6709a020d4d717af63520c8b15aefb2e351805a038987
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83734);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0708");
  script_bugtraq_id(74382);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur29956");

  script_name(english:"Cisco IOS XE DHCPv6 Server DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the DHCPv6 server implementation due to improper
handling of DHCPv6 packets for SOLICIT messages for Identity
Association for Non-Temporary Addresses (IA-NA) traffic. An
unauthenticated, adjacent attacker can exploit this issue to cause the
device to crash, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38543");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCur29956.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCur29956";

if (
  ver == "3.13.0S" ||
  ver == "3.13.1S" ||
  ver == "3.14.0S"
)
  fixed_ver = "See solution.";
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# DHCPv6 check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_binding", "show ipv6 dhcp binding");
  if (check_cisco_result(buf))
  {
    # Output is "" if  no DHCPv6 server
    if (preg(multiline:TRUE, pattern:"^Client: ", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCPv6 server is not enabled");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));

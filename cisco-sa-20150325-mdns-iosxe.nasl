#TRUSTED 228fc928093dd1d243100aadbb1b091c98eef2866684c495c62a4ff2e9f735402b625bf2cfed4a1833cdc4df215a37c3dccd6acac983970540ac20a0420a3220e3f5975fb59ca6d489416a6a85db59aaee3ef9d116c46f3f019401888f97008550011cfe73b044e27f66939c05358825b70cbe8b08232dfc140f9d6c5d497a0f32e416b37d1cffcf2a1e648012b23fd5df522fba3bc94298d0d81d37d9f0cd2a02e26da1d3a5de1a0fb9aeb6ea21bf7adb6e46f9e83b00fccc5369acdb184f6a2a3362bbf4a23c3a37d58a95f176e9672b6b592190a176bac6fb960a8c3464e10ba95160ebf9bcb0a290b864f5a992b6d4fada19dc1e40c7ab0792299b7850cce61b6a90163094fab07885c059cf34ee7413c019ccb1380680efc95dddd526809881947b7587a85fd3e34cea32d22c81d6ea22e73cf53cb9c24ed2ca34d2bdb04a48ab3e09d1cc126d4a9c7d32a455266b000be5f1ff5b8d66dc7d19ee2c93bd82649259ee9c5673c6bb6a4c81beddfee89a182d1625d9af950514ab0252cd18a3cc34af1ee6916529e70146163501ff8236f865733b6216dc65f8f3dcff508c4004f070e9a37623dd112a2216e56272b406fd351f6579f355588062db1401baa13ac02b3905193e06e1bfa19fcab9b67f8d539c208cfd9a19d07ee2a8d82f7cbf8c226c1fddf0d0c36fa846e07fc107ba2555b2845dffe99ad502dae853227a
#TRUST-RSA-SHA256 9711514249899dcb8f14d2ddb8d2cb81fbd656002a30c15701fa089a4bc01f9bb7bf1bf0b7db7cae0529ee692c4b3dfca93fd39c64fe9b4e984a15e3aa636424f495862665a9cc63b74a8c880a1467732d9b8343b7d01fdcdf0fb2d5fc70d7d42c1c40765ded63c5cf21585ff830a2ab61789b14a361b5c29e42c20adbb6a8c17503a6dc55ad97d05831259e62f4cb78dd2ed5e83adddd7acddba0170433099488cb46304ad3b086c0b80e980accfaddf5b150945fabf0ccb8389c8545c41cd3b6c7b4d65714d8f6dcc2ea52174c35ed289978f4a89b96da4c7dd606183b02e8ca8003767e407dcf81fb2052a2b8e0b41c049748b24a6510837ea5ef805bd6d3147c6365dd5f30005bb00a71c392d973e98325a35e1bb944172fbde8c02bc90ffdcdaf33a26ef13b11fb2025a3179baf8a3d8878f6b212ecb78bf704cbacd4a1f8678b7a25beee3d9f41add0c6af11af7f36376d720863505258a32b3ea583071db591c3b77d6ea68ee514089df26e199b9e31079d4f3b9de71ecc09ad7868d0b82a6aad1a43eda20640671a6677493ab0696b3bf75989a5f77e9fbdfbd8980cc6a81bed61f33209689cb7393586eb0367709db598d94bcf66d367011ab5a05b02b1450622b7c2f050886a2df84e4cdc6e41e0b1b10572dbf104c67ac23da301ce1b3b77e0544af71b20d67f50500cc01d4bf2dc3d23da364ff3fe46b3af7ed5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82573);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0650");
  script_bugtraq_id(73335);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup70579");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-mdns");

  script_name(english:"Cisco IOS XE Software mDNS Gateway DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is affected by a vulnerability in the multicast DNS gateway
component due to improper validation of mDNS packets. A remote,
unauthenticated attacker, by sending crafted packets to UDP port 5353,
can exploit this to cause a device reload, leading to a denial of
service.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup70579");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a10c73d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37820");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCup70579.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

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
flag = 0;
override = 0;

if (
  version =~ "^3.3.[01]SE$" ||
  version =~ "^3.5.[0-3]E$" ||
  version =~ "^3.6.0E$" ||
  version =~ "^3.10.([0123]|1x[bc]|2a)S$" ||
  version =~ "^3.11.[012]S$" ||
  version =~ "^3.12.[01]S$" ||
  version =~ "^3.13.0a?S$"
) flag++;

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_socket",
                              "show ip socket");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+5353\s", string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override++;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCup70579' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

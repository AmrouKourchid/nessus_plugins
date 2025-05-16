#TRUSTED 29f7a9ee2812f66bb2553c8c26746b91ae9853fce4c9652318f1b6b6e70cc67a9fe27f68663cc92974dc0d75d04209869267d5dc5feb0d0ed7e1096ead554d60d59df7e04d73972e546bfa5b759d01075e37247489a96654bdb1884095e20a7af262ae06f09df92a35ed157d11e3a988d36f81e2036c66d1e920c820230fa9de765844adfa2ac7596c37effbb2edb3c100fa5cce550415077e0d45cedcf8825ee37544b43f251b978381540319196b60f8dfcef121b26b3f83f7eae65d94bd940019ba251870a4396fc0e40bca31fa71395d05711b0026fa5f10853060b14e61ec7c6046783fb627fc8edaa247470c26b0eaafc76c7e52c255e64e558dbc7c0be77e28fa47b9648f61ce2544f662a0285ef545215dd7c6922a9f18a8280aea575083cef9503b6f9ab6afc732f56018e958e2fbfb819cae74b5598f88977b8e2c953d1612f606cd6ba936bb2a524ac721e0db3d910e389e01539b0ff85fcc42b9e31592d5ed1b11ea11b37ad8fcc79bd77736b348954ace8ccd6cf9f3b69f8d803ea7f69f4081dbb95706fb2f989e3b17eed3b74b03ccab793f921e2a3e6c6dd267dfb6c6694606512c6647a288426dd8e074dd74879f47c02f00fc8a36ed0864c4410f87078ecbdd6632530f4a77e38cb87784449b7b5bc853ed74a57d63c5a1e1748fa59749b3ece21f0425fd50a4d12882e8e51e89109a9d68565164c3ae3a
#TRUST-RSA-SHA256 71f352b94a213790c988ddfcd266ff0d37c4f30f7065168a40740b01045a1ade5499da3c8296d545b97e84b1e67a79f0fd9eeee4837fcd37fbef5030f4cbaf86e2d1124105842e728b80190313e2575ca4d4f0d6fc80857dc8e2f7f70d0c110bf2dc2af77d484e88ae3b7a3922ec9be064869f7885cd90746d718804d94be95e337701e1b04e567a99b0c5fada894624f24da5e43eadd39ce18ee9ddf0579131cee929ee3099753d89b9f4d34d0e9a5b00c0a3af32d5db5733914f4687fdea55c84b14bcb4f1d0fc69332418c09f530464f37199f656b692e7eeb643e1123bbff7b6790c41b00e005c97027f9efee657cf156b31259073510ddb4a78d7f6bd9601de7761073f1c553fcafad9ba149ce9f2fda891288af9d2bb0aeb17cc916b61ca3da6b6ccb38ee8a9c42aae96455590003de73b8549d2f4ebf45ee9314f73d02a84667aeda849033ab5594dada0f298baa9a56315e8414b3fa18cea9cbf114c53df5b99ed024904a8c2228b6eb7a59d8280d82194f70800addc709c6f1b4e8848b24aa316db6866e7fc6de88b26915c7476e0dea3829b51eeefbec0c251dadac086cb91593a373bbfcf7c070b84be7ca6289a329385ca4071a5fbeb32c3d7aa6bc73b20878c8fd0126a99f4674a5096e22f17a5955f6b2cc35a873e8fd89287ea54b9db7aae25b677aa9523d1c74ef5f41f99e9ed6414992e1b76f19d9b245c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93193);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-1478");
  script_bugtraq_id(92317);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva35619");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160804-wedge");

  script_name(english:"Cisco IOS XE NTP Packet Handling Remote DoS (cisco-sa-20160804-wedge)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by a denial
of service vulnerability due to insufficient checks on clearing
invalid Network Time Protocol (NTP) packets from the interface queue.
An unauthenticated, remote attacker can exploit this to cause an
interface wedge, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160804-wedge
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57eccdac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva35619.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

# Check for vuln version
if ( ver == '3.16.3S' ) flag++;
if ( ver == '3.17.2S' ) flag++;
if ( ver == '3.18.1S' ) flag++;
#if ( ver == '?.?.?' ) flag++; # 15.6(2)T1 IOS == ? IOS XE

# NTP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
    if (
      "%NTP is not enabled." >< buf &&
      "system poll" >!< buf &&
      "Clock is" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCva35619",
    cmds     : make_list("show ntp status")
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

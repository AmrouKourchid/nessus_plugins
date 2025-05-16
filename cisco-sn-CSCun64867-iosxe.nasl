#TRUSTED 45f14775958a36805d96e2a06529a36114d2ed2b9acd73beef6187535a94d3083cc74e89f11346d14188d332fe73eaf6de474d312b9a8d893f07489d33e688c5a6016730b4b09dc6d05392b57c3e0c401ebf16071b879b55f672b3b1d2100b77cde48fca2ef6cdeac63ba703a7983d8d779a687f21294a2044e180f9d789ab9c5f45a87800056b013b13e610afedc5296d861beb96e2303962f14c2606c3c486789219d29711e8a9c50b1598b41a80da57a1b26fbc75fa0a17550b61e555ff7dc86d5a51eedaecf00148f4b6bdc3f8272eb52ad70bc544941ff22acb333e7ef99e180223884c0c7fa7a20db1fffb937fa3f2abdcd2856fcb2afc4dbaddc876e9a7dee0958cf9379b2f58893d1ec197177e43fef825fd067be169aa2b83e2171d607129b1ce5411468c82f8ed7ac58eb0bd350ec4bb09cf9e7217ccfc645ac123229edff6bcbbe750b0cd170bd4a6498e6f3dc7495cc2b5812824a5637a9fd7c465c97261789770dc2210501a66ffe0cb5ca58310c04c0894a3b8abe68c2678a857651e263859e8e7431bf45bddc043f55a0e587cc2487766ba5e03e126141acd4572eda55775161743c2ac42cff8dbec2868e71860deb62b6fd0580a8011fb7009b796c469fa7e6f99e1516cc8ba45a5bf63510030fbaf7da497532e4520d8bb26e3be554a78d58bc9703edeba9f78b7c99c030f824cf9f8657d355905cfab5d
#TRUST-RSA-SHA256 6ac6b5df722b04d4a0878edf9aca3cb4c6f68345ef0612d83cfca6700fcd341df5b0da4a0d8792a9922c6311a22b1ae99dc671dfee994c388429131e1cda247d0614a17525833f78a34362da11c072531c1fdc753a6664c781bb935e8f40cc5bc721c6d3dccf46f050d097cbb99cfdc83050d7ce3b08c1a28e36b68c4675d10ca4eaff02ecc13cff47d81fa84b56ad7072a289802a0e5e9ccd267335b60e1b3ebc47105e254fd8c9b595a94d73c47933bc8f23396e4b97735a627843f08268806d00689d81afcd35a94eef848cca5123596f7d17a1d63249d481e9001d6e222ada7ebb7a2b0638a2ef1ecfffc78b22cdf96fc066b6380189e6fa003ddf24405ba23737ea4fdb1d9526d055dcc184f9797030c95aa13c6a81c17db5d07bb1a55ac217ba9a4b0dc24fefae97e51a466500bceb42359f60eb9e54e89298cf6f71d8fb9e2f4abeba0a1d70930e6d3cd739129332c51cc6f88cb182adcf5ca4d2d72a8206d49705e7e1359bfffe4a3c67ffcb01880ffd60e74eb4722b3bc94a8f92544c7a4319abada62b4c07647ec997232525535dc441a0517947ccbc0f4bcaa94f4e8166a625cace84b65fb9d2a140e5cc518fdfd3c9949f409af54c2dfb2c12a4a0ca3b9579e1cb30e50ae36bc536d0e756298183349b8a1e37427146d5b50b4c56899bc6a825feb7a1ae91208a99540ac1df2aac003957f07fac9efb265682bf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76972);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3290");
  script_bugtraq_id(68021);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun64867");

  script_name(english:"Cisco IOS XE mDNS Manipulation (CSCun64867)");
  script_summary(english:"Checks IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a manipulation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS XE device is
affected by a manipulation vulnerability.

A flaw exists due to unconstrained autonomic networking with mDNS
(multicast Domain Name System). This could allow a remote attacker to
read or overwrite autonomic networking services.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34613");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34613
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a0809e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCun64867.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

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

if (version == '3.12.0S') flag++;
if (version == '3.13.0S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ("mdns" >< buf) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCun64867' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

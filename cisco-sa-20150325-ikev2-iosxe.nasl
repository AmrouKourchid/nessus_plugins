#TRUSTED 28cf7eabcd9aa82a8537ab62740b27daa159ffb09a22f34f3c183481fff96f89588bb680a805f1b83e0b9065500130ef4432c4a6a137193e7461d5a617c0e614fc6cd455e28691264b8c37271d25500dbd64e3899f0f9f9a2e51ef3e611b61989983fce715da5c02a5f116c9239227d9ba9380bbedb6286501e7d0d84702eb2b3822fd23d9ade7d7f1f8fc95c26d1b63fc65a1e78099a0488a9bc349e6cb8f069b063b8997cf3640c700f60a64cfc38c69101ac94bd54a58b890d50aa3ea7966d2ad7600029e661eace9218912d1311968e7f2ad8275866ad67c8f8a4ce1e76ff7c2972409e918b8409e39d31010fa6a4ed9e26322542c4abe02f737798e5931f3c2f29463f9c55c874a01a8bc3d1f81e5e86ae4c05db644e3a731abd2da287c67ab42419e9b95acbd733af3d08e75b5f69a6f1b28efd64ebc42b00daadb982df9bace33a63d7bca33c414fc55278c02190c9091dc71d9842dab148817d7fb88b0345fae9980ad51dbfba04de8abf75ead5a82b43020bf0171eeb58bf7beb97cf85b37a99838a336debaabf0fb3cff5a1d73ab503f748459ff34a4a102bfaccea120a472143dd860da71a1d2fc5eac528517a2fdaf86730c7e28fb8b0798e0b2f8a0742a176fffb0187de4b16660c00812810f18f0ba39af80d8471a26c349e146feee0a0b052a7b7de748c50d58ac776b4591de38b561dea09e4fffc8b8a99c
#TRUST-RSA-SHA256 65b6e0e6046f5d1cd210092cc05617bdf1ac314a395130cf2b29cfc98c10e99e69aa8110f98d21d94d4cd97c69782fa3827f9d72983109dc08da2e9502e612d27675af0c349f9efdce078314f2adf534be1c8499cec081aac7fd62aa015cbd6dd059732310f7a9e34255ed7d52b6feb009da60634d233ec428423f73532bbf455041102c3d6ac4bbef144e211d134a28d5e67c697beba77a3d4ee9aa24a63742f6daa34403a969583d2b6e37935c8f8a12a24ad0c5ec1768c38a4a2811ce7b4fe7b4bc5c07fad55d0e96d2b9fff79ff9684e7935a673e859af0f851b589a76e59070f10edd779cb7245f969ca3af2ca73e9a601bc4a0c5e75ca3580aa99d6993628917c3a81b22d5ddf9bb7e111474fb619f06deca5105122e85bf08c3a71e49ef1df5a23c7600ba0a15b9b1480abe9b2dc041fc5a7a1eae0caef658981c9b06ac11675009c5a6f416478a154ae000b2415a6caed2309afbcdd6da8b0a24184c6feec123295bfee761ef244f17b663cd324b85a826ba370fb93c76e61909bd85c1c0583f10fcac1a4f6d28b06c2e5eef57024b655b7195d96145cf2b3ef15113d9cb1c21165f4facc9f4761504ebf5742baf30810a1ddf7f33ba2b1ff191be92fc29bcd9a814d8485248bf3b49fea1be56b14dc6a5e2d45fa80b86174c279cedd77317c6a146018bb9e62a198312ce29bddb45b1935db14b675cb03a186f30b5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82575);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0642", "CVE-2015-0643");
  script_bugtraq_id(73333);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum36951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo75572");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ikev2");

  script_name(english:"Cisco IOS XE IKEv2 DoS (cisco-sa-20150325-ikev2)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Internet Key Exchange version 2 (IKEv2) subsystem
due to improper handling of specially crafted IKEv2 packets. A remote,
unauthenticated attacker can exploit this issue to cause a device
reload or exhaust memory resources.

Note that this issue only affects devices with IKEv1 or ISAKMP
enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10464ee0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37815");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37816");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
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

fix = '';
flag = 0;

# Check for vuln version
if (
  version =~ "^2\.[56]([^0-9]|$)" ||
  version =~ "^3\.2(\.[0-9]+)?S([^EGQ]|$)" ||
  version =~ "^3\.([1-9]|11)(\.[0-9]+)?S([^EGQ]|$)" ||
  version =~ "^3\.12(\.[0-2])?S([^EG]|$)"
)
{
  fix = "3.12.3S";
  flag++;
}

if(
  version =~ "^3\.10(\.[0-4])?S([^EG]|$)"
)
{
  fix = "3.10.5S";
  flag++;
}

if (
  version =~ "^3\.13(\.[01])?S([^EG]|$)"
)
{
  fix = "3.13.2S";
  flag++;
}

if (
  version =~ "^3\.6(\.[0-4])?E"
)
{
  fix = "3.6.5E";
  flag++;
}

if (
  version =~ "^3\.2(\.[0-9]+)?SE$" ||
  version =~ "^3\.3(\.[0-9]+)?[SE|SG|XO]" ||
  version =~ "^3\.4(\.[0-9]+)?SG" ||
  version =~ "^3\.5(\.[0-9]+)?E" ||
  version =~ "^3\.7(\.0)?E"
)
{
  fix = "3.7.1E";
  flag++;
}

# Check that IKEv1 or ISAKMP is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";

  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:pat, string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s500\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s848\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s4500\s", string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (fix && flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCum36951 and CSCuo75572' +
      '\n  Installed release : ' + version +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");

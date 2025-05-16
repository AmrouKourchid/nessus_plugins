#TRUSTED 14f80233e0b5ea0e54b0381fa58f83d3665e3652861116544eecce6dc3749f86b709433d18761b2812b7ccfb10be0f90e5eaab6ad06e241105910c33d2c4689ca6d75f7400e6152b18e6fb94a845c40f84349d7ea2a6c826fc33e17e63254331a50b1966a50dd870ead635909e4c0f173da38dbc4b0acfa5f9f93a17035826b311b7bb4179ee907cc611a8533e3351caf217f966c230faaacc71eec547495279862c5e5ded66ce8372d01ee35b1bdd44569e977a2cd92dbd8311dc49cc46b164a8b7fb2062b99c1443c7df9a2afbd66214c628c9e60a3e42940a20776f61dd4cc3c89255a70ee7c1d313af133744f0260d45f42538942c49b55d26f97f21c6c4f7642bc93dd2b461807d5ab4999ddbf6d022e8be6855635f6c48be611241ec3f282df6af10e1c6fa7838a38382124f202b14951ae409d2571a6abf400977727d9846bee3192c86ca7ec6e2bc8539a04968f4c50a8f2b475fd856b8be8b85c89f8b0a70ca679342125845ade300cbe0633ee90f0d379365e3ca493fe09c2123d8a396b793ba2d22bfc981551430b27380c330d7d936ef29726547e1b8a49327bd66f0329407851133c67a0291af93cf842c199d933c255f0322ad3c8d5e722ee815ed4fccc6c1a7e5d54e8a164e9f8ae4463894fd6c0aed0803d4e197680237ff727b87d658fc82a13a4aca027a152010113eccc4183d49b4826edb46c8addac1
#TRUST-RSA-SHA256 3edd3b844ec27a10b5c5bf55824a552dad0bde27e500a08cc9ab681d29574684947a0dd3b7d5e7d47963beb55b3a23db53afc6d0ba9ef642190d1656d93245e65396d55e442d7ace2dc145d9d38688830029b0c84ea2abc8314e1401d8b6ddebc1391007312673ec0a0ce275efe979390bc4b1b98e29f2860b31e34ed1ef7572231dcf0cc201cd99a2eda7e17ad126b610fd270015ac3cbf9ffb24e62c46c413d96eb38ba3dd7d75e8660e75b955a08039d911bfec5b38e811846570181d9cb767caa82d9745774d7d2a34edd05ca6042a036ca76b740b5d26a9cb219f52d8d69f2ca613fb9db78138ff8159944da56cac0529ae4616527f29697c6d93a1e761b41fb9435821d15a8dd242c20a3b2127a15ad373e7876a5772a7316e817ee70062f17523150073b5fb7b02c10d32777c88d07c611da99692c44dd74b8c637349640b63bcf07fa2d51b02b666f2f85a351fa5ea41626c3e8c2cf7e44460acc5a554d129b12027966971ea5240755f695bbd4662c6812545669f1620cac045d6b2cce63f1b25c40d25fcf2baf1a005fccbee6360a82c6eafdbc565d14c35439b0e347abf1fc75d4df2427d66fbfb140d71543f45c4c1af663f98b6dee10bc9a717ec2712de76db5a7e07e6fee3a1b20f8a1a13661222e2ba80147b1d49ea65011e2764ac9fc37070e4cf8907a3c9759c14b3aebf018df498bcd9d3ddbd86531cb1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81594);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69732");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco IOS XE GNU C Library (glibc) Buffer Overflow (CSCus69732) (GHOST)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is affected by a heap-based buffer overflow vulnerability in the
GNU C Library (glibc) due to improperly validated user-supplied input
to the __nss_hostname_digits_dots(), gethostbyname(), and
gethostbyname2() functions. This allows a remote attacker to cause a
buffer overflow, resulting in a denial of service condition or the
execution of arbitrary code.

Note that only the following devices are listed as affected :

  - Cisco ASR 1000 Series Aggregation Services Routers
  - Cisco ASR 920 Series Aggregation Services Routers
  - Cisco ASR 900 Series Aggregation Services Routers
  - Cisco 4400 Series Integrated Services Routers
  - Cisco 4300 Series Integrated Services Routers
  - Cisco Cloud Services Router 1000V Series");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69732");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd2144f8");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus69732.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");

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
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Model check
# Per Bug CSCus69732
if (
  !(
    "ASR1k"    >< model ||
    "ASR920"   >< model ||
    "ASR900"   >< model ||
    "ISR4400"  >< model ||
    "ISR4300"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Version check
# Per Bug CSCus69732
# - top list (raw)
# - and bottom list (converted)
if (
  version == "3.10.0S" || #bl
  version == "3.10.4S" || #bl
  version == "3.11.0S" || #bl
  version == "3.11.2S" || #bl
  version == "3.11.3S" ||
  version == "3.12.0S" || #bl
  version == "3.12.1S" || #bl
  version == "3.13.0S" || #bl
  version == "3.13.2S" ||
  version == "3.14.S"  ||
  version == "3.4.7S"  ||
  version == "3.7.0S"  || #bl
  version == "3.7.6S"
)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCus69732' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

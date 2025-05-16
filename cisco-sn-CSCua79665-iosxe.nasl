#TRUSTED 857f3f5fdaf58853683ecd107ef56b144dbc1b8e18b46b08857f039baac45d41209e538ba14d33b4c3754f2def36b7aebd35ae4603ca44ac9cc214cce46bb7c2a278108a75d86b41c9e98bc9bfc2994ca26b4d3211fe63fc0779cac948bed1f55690d72cc120fa12ef669d6e1a543c557a434aae3c77ea9149aa3347fd3d9466f53630885b0657b6e6190f31e68532312b59ed1ba59a5162daa7797f5d89164e6a5f3a8b22a09abebff99351e88f72b7405588feefcfa86cab995428baf94807ed37d0c734356911633b8428fdf255a6a6aa28947d5680f4bda720be9ebfe77bc6d4430d82380b729bcfe3fa90cf8b14b99bdf7289b608222b70d111cfa0b16ed63ee28cd67e538fb9edc6547e38dce0a43c96b83a6d4723e9cadc327f203f6f7a3bc6deb899e6564563d52bf11bbc03a944b18ffd3a69dc4cf2da331314eac7ec08379e16a956e73ebca736db8da11e4f39f9c799ea8d24eb26e8bd670445ff59f24e1bb0b24b37198243fc6b3236f87823e880e096ec8e9451c128ea36a881b1328390b8a449543aab5631d7291248b8846acc7f702959fa0a6d5f92a30ef8ef31978d6ed6937958c5b06064b9ccad21e2dfae6d2f1826b2a06b4ba7d5ca2847a0dedd1eb2d3faa22490b3ee74b4ee7b26e90676a5c90360a00b0548a8ac433af7a58470ce2b00bef09a71aaa517e2f25b631827a18932714517e7159800f8
#TRUST-RSA-SHA256 0418d4688078b0be1b7ef912def424a36c606cbd0bce705780296ff9d344763a8337f8fbe0a2fc2e3befa6fdfa8777cb1dfb0a67bf3b54d6b6d345280e8d354f972fb85336cb81547b6f317886efa2317a018892f1a24575925cdda3dbe0e1e5919898694319b8b27da9a1d146dd9f2a7af3027efd84d43cb14538d6421850bfb8a7af446f80dd11ccdcdf1971275f771bde4c27fd98365730e5308dc3fd7556c9285dca33180ffff52f19f0f10b2b60cf3ed3beebbe9269f7e1f34ecb091bc5fde2ef4f8f6c792220d342a05e081baf224c286d1d6706f133102965635d3449aaa58b3a97945729e67acb891461aaed94d6ab849bbe251f8965435003d77dd19b576c0362c3c8ca8b6598d7943b8f1645f4504ee1f4e9f5555d673164b6b751d36a9447120ae3067dedae2465ea3a15ec4e6141bc2c05a94bc9b2a6558476cf73faaaffe06d44bc385b580144da20f7c4f1b61afe7014d76a3bd2d67be2167ccf875a18a45bfc6017ce6f5cb16a8d126a9e8d8bc0dc4258b81fd86d7ef1d63ecb30201e7401eb3c094a8aa80593a10e2112ce1c3dac25c38457244bfbe7d6b8d50b53878b85c3fc0e8c2c8af0662350c10f2bc4b8f8f0845e15e74c26d165b369038fdf967cb4f55131ff9371b1cd045af10af0bb1ce5ffcaa320f86fd8da44841c2a56c98188c100393122c6209d3fa5666387282aaa2092d1179ac2d10f7d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82586);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0639");
  script_bugtraq_id(73337);
  script_xref(name:"CISCO-BUG-ID", value:"CSCua79665");

  script_name(english:"Cisco IOS XE Common Flow Table DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability in the Common Flow Table (CFT)
feature due to improper processing of IPv6 packets encapsulated inside
IPv4 UDP packets. An unauthenticated, remote attacker, using malformed
packets, can exploit this to cause a device reload.

Note this only affects devices that have configured Media Monitoring
(MMON) or Network-Based Application Recognition (NBAR).");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCua79665");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

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

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Bug and CVRF
if (version == "3.7.0S") flag++;
if (version == "3.8.0S") flag++;

# CVRF
if (version == "3.6.0S") flag++;
if (version == "3.6.1S") flag++;
if (version == "3.6.2S") flag++;
if (version == "3.7.1S") flag++;
if (version == "3.7.2S") flag++;
if (version == "3.7.3S") flag++;
if (version == "3.7.4S") flag++;
if (version == "3.7.5S") flag++;

# Check configs
if (flag > 0)
{
  flag = 0;

  # Check NBAR
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^\s+ip nbar classification tunneled-traffic (ipv6inip|teredo)", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

  # Check MMON
  buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map-type-perf-mon", "show policy-map type performance-monitor");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^Service-policy performance-monitor (input|output): mmon_policy", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCua79665' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

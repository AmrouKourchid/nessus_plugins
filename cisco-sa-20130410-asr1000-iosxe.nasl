#TRUSTED 8ff31c7bdafb2a154200bc262fe6cea2df85d7bf515443e1d1bb2a2d833417c5b4c363d9af22b672afdeb5fa42b7d5b1a5c65ce1d083966d0a4f6853c443793599a2810eddc6385b88647a55a7fd81b8892737b60118321651a4cf12c4a12bc599985f061ccd038724620e264e1536faf9630b85b26dd8f27770600ca675b0eb9cf87feb7631b7997bde736eddc96fb21cb5a846f8b696b904716f5b0da2ff5d15967c86d304f72242f5147716e9880226f35e31e2e9e662a9ef1fb43df4ab2030b5ea1b1d90b56c0c856efee53c974095d33bad537d31885bd49c431a21b1a6d13ff89c4402383323277d1f99a113ffa708afe4bb284e8d22c4954904508951d0a77369456fa3fe07490a8b079ac04879057fc6558e3b4bc1777c583753ff433cae523ed8ee5789a85af0b3f4c8ac6a370df72f2e82e732708322dbb4c1b94306ad4ab021aeee4bb9df9907adcbf5d8ba9c1db22741bb7766672fcd0fc8ecfae099e71a5ebdc9b29b63f74ebbe3ab133b44b980c0e82e45892bf116214f98e06039fce0e177f287db0ae2fc2177e0c3439fb9b0cc230246d8c0ae27bf244135e2bf78712ad7ec82ab64f6494d43277c36a51db7b31b881fe12216aed468728107edcd1a7d1daaafe6e13c959617d9ccc1b821aec6bbbdcdd7030b0541815617f3b3f067646c23cc9676fc2d5616ca6490840b04f9d0de51d7e46bd8ac8c8482
#TRUST-RSA-SHA256 9e896b28558b400322aa3fb081214acf0a184eab39b9e7d9db6777ce669c606e93200ee6d7a577c874728096b6b0717e17c31b2e576146b61e419d7dd52a20f3a852d454dcc2441cca969390359a4ffad48dcdb505199ac17c61ce230b57f7ea79a5a0244d8158e85fa9b87e19fe74bb031cb7126d1a91db741332b4abe9a215be3fba04196ee7a5607ef3377c1c2cc1c9c2ad6d4a39af6437e7bc607fefb4678294586f2a22088e0edd02adbd79e8aaef1c0decf2be9ff4b6bd04e1b6cac758179959c4f8ad98cbb3cba2d4d0a2f86d21f7f5bc58011f093e2ef17057ff403468f4baf50b18f160a8303106df8f45ceeda5b8fcec6c16b22aa88bd41ab6b57b188e09297b1f2ac1356a3ff227620618256fb5ba8288d0ca2f437a9ee47ddb7766bc3244b6f94b4d11eab1652cf8ae156cb940ebd43ceb826f1c79326c60654fb07d996b0be62e2eecc0a138bf14cde8ed6af7b2fd08a52875bd5e1dd3f11b832176b922fa27761d1e65c36f479bb2e42b4bd9cf3ff8a285609e5f8f28f4d3ef7254dd160ceb8f14d40af97606b3427022cb4b95fb206294eec1146868a813349103c983c9f998bce89c4a75e8569a2d88d6c19b491044f081e406afb1ed035bf4ce2f5f1183e83e2d1730cd8b051857b6018c0eb8989ed15d32e18a8397ff4d0f13c918ecc055fc10cf71d52684e659f7c75edc9cda7ada530a77a236927359
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67218);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2013-1164",
    "CVE-2013-1165",
    "CVE-2013-1166",
    "CVE-2013-1167",
    "CVE-2013-2779"
  );
  script_bugtraq_id(59003, 59007, 59008, 59009, 59040);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz97563");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub34945");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz23293");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc65609");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt11558");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130410-asr1000");

  script_name(english:"Multiple Vulnerabilities in Cisco IOS XE Software for 1000 Series Aggregation Services Routers (cisco-sa-20130410-asr1000)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XE Software for 1000 Series Aggregation Services Routers
(ASR) contains the following denial of service (DoS) vulnerabilities :

  - Cisco IOS XE Software IPv6 Multicast Traffic Denial of
    Service Vulnerability (CVE-2013-1164)

  - Cisco IOS XE Software L2TP Traffic Denial of Service
    Vulnerability (CVE-2013-1165)

  - Cisco IOS XE Software SIP Traffic Denial of Service
    Vulnerability (CVE-2013-1166)

  - Cisco IOS XE Software Bridge Domain Interface Denial of
    Service Vulnerability (CVE-2013-1167)

  - Cisco IOS XE Software MVPNv6 Traffic Denial of Service
    Vulnerability (CVE-2013-2779)

These vulnerabilities are independent of each other, meaning that a
release that is affected by one of the vulnerabilities may not be
affected by the others.

Successful exploitation of any of these vulnerabilities allows an
unauthenticated, remote attacker to trigger a reload of the Embedded
Services Processors (ESP) card or the Route Processor (RP) card,
causing an interruption of services.

Repeated exploitation could result in a sustained DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130410-asr1000
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ee7b008");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130410-asr1000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report_extras = "";
override = 0;
model = "";

# check hardware
if (get_kb_item("Host/local_checks_enabled"))
{
  # this advisory only addresses CISCO ASR 1000 series
  buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
  if (buf)
  {
    match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
    if (!isnull(match)) model = match[1];
  }
}
if (model !~ '^10[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# for each cisco bug id, check version and then individual additional checks
# --------------------------------------------
# Cisco IOS XE Software IPv6 Multicast Traffic Denial of Service Vulnerability
# Cisco IOS XE Software MVPNv6 Traffic Denial of Service Vulnerability

cbi = "CSCtz97563 and CSCub34945";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.5S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.6[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_ipv6", "show running | include ipv6.(enable|address)");
    if (check_cisco_result(buf))
    {
      if ( (preg(multiline:TRUE, pattern:"ipv6 enable", string:buf)) && (preg(multiline:TRUE, pattern:"ipv6 address", string:buf)) ) { temp_flag = 1; }
	  if (temp_flag)
      {
	    temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
        if (check_cisco_result(buf))
        {
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP40", string:buf)) { temp_flag = 1; }
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP100", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software L2TP Traffic Denial of Service Vulnerability

cbi = "CSCtz23293";
fixed_ver = "";
temp_flag = 0;
if (version =~ '^2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.1[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.3[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.5S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.6[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.7[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.7.1S') == -1)) { fixed_ver = "3.7.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_accept-dialin", "show running | include accept-dialin");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"accept-dialin", string:buf)) { temp_flag = 1; }
      if (temp_flag)
      {
	  	temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_xconnect_l2tpv3", "show running | include xconnect|l2tpv3");
        if (check_cisco_result(buf))
        {
          if ( (preg(multiline:TRUE, pattern:"encapsulation l2tpv3", string:buf)) && (preg(multiline:TRUE, pattern:"xconnect", string:buf)) ) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software Bridge Domain Interface Denial of Service Vulnerability

cbi = "CSCtt11558";
fixed_ver = "";
temp_flag = 0;
if (version =~ '^3\\.2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.3[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.2S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }

# this check may result in a False Positive condition
# as it would be impossible to create a check that handles
# 100% of configurations, this is a best effort approach
if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_interface", "show running | section interface");
    if (check_cisco_result(buf))
    {
        if (
             (preg(multiline:TRUE, pattern:"interface[^!]*encapsulation untagged", string:buf)) &&
             (preg(multiline:TRUE, pattern:"interface BDI", string:buf)) &&
             (preg(multiline:TRUE, pattern:"rewrite egress", string:buf)) ) { flag = 1; }
        { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software SIP Traffic Denial of Service Vulnerability

cbi = "CSCuc65609";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_ipnatvrf", "show running-config  | include ip (nat | .* vrf .*)");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"\s+ip\s+nat\s+inside", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE, pattern:"\s+ip\s+nat\s+outside", string:buf)) { temp_flag = 1; }
      if (temp_flag)
      {
	    temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_ipnat", "show running | include ip nat");
        if (check_cisco_result(buf))
        {
          if (!preg(multiline:TRUE, pattern:"no ip nat service sip", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------

if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat());
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

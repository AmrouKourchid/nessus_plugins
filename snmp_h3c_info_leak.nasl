#TRUSTED 065fc3a67bbbff701b8109378fb2ac5d5df9f9093003a55126c68f21952c586189ddb4f4882a413e5742ed2d9dab715e81b8b34c615c69e94d679053097f7c44ff92e2785801f8c50a4bb5e540e54262397909a2bd4c540fff62eeda60e16c45a736c20e483f9dfae32173d7287d2990d9676093e7a22346857fb440f5109a816561f00c55505014bc1202000b6dad1738278700c1fd82737ebb8467745b98c595f082a2322ae6f8313cb682f7fd26cacfb51ceda49c576a9e22066854d6c31cee600283eb79701f55dbb50056e85034a4adc24546a0aa24162b4b0bf201396005807ed6adefb8e9212edc9362d6ad4d0e781c6c2eb12970aef91f14041dcfdd6f4c579be7eb936ab2c83a6584b7986c2525087f277a4746beb79f13bf4c2a71ff90609c90b7e0a3d6df0e750ae17a22738333927ecc3cfcf4dcb7559466ac942e06b449d5ba500ed4493ac54bc536be973cd8896b32c9f9d36a735324027c099ee98acac0a2923543b2621e245325d4c7cbb4470e1b095ba8478a58a5ab67bc4c3798ddb8110dbce38d221eddfaa69b7981426604796d9a11daccd2f30c3a7cb47150bea4f11a144e2eafbd7dd8c9d99f70e1ffe5897d783d8b374e5d48cd916d3117bbf832b4430f988f569431b5da76cde1e0332d59ee563c28e69cd18effee1a9dd15603ed6bb9272ca0b99b2ff42f77162ee261d8f0b764393bc1cb5dad
#TRUST-RSA-SHA256 aec6393fdc3a037fca9cb40f54f1b5fb73ca0140528db35d30c2adf897ed1868807d88aee58efaa5313db3875f427de5479c22f0bd347347485a7e77a372d6b5ffb3887e9df532745ffd199559e15364749f9ba68e4e33f0e71e80775b33a82292b605dbd04a4e8f28e2fcedce5c1e925a01c0732aa30dc2ef599c5e655d27a978220d20477b5f13065fee7265da1b840cc7857b8567f3a442b18af550b99f2281240708e96c210d278da3cc82db7276fa6f85ba6111d54da6c7a5f1a592d16f5afcba47a5f758e890cc12a98617752b2987f8a5edd1cba7317db4d62ac0c72c50ce1b6765b4514e2825e7eb1ff3f97b6aea9de0a39aa4da9802f44fd872d00f215c8375d3ca5b5ec3a4d8fdf3ff0a27b7042646fd5d930c2bb051510b43501f4b8b27ea6bdebf55b45804cc70e40d6deaf8ef1d55d90027c7918a2c628c26c4e1cd246b4c85324b4442626c79c526810371a38dc8d2d0b37fbde2655684aa3f67934db281271a97636ff856818495bbd1d59163bd17347eed049c90e43b61fc576c000b1f9e64af346a139362864b2a50b6a1db25ae23bb42fc210e56a0a894ff778620585157324d1bc134e9eff2b8f77386bf5325ee97aef57ab3a3417fa23e33ed245e5775ab2ac3ba46fcd92490637fded02f7046f05d8366567adfd5dbcfff57fd3d9aba834e05a0d745f44a7ccd799b244ca4dfedc5529bec63cd099c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62759);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_cve_id("CVE-2012-3268");
  script_bugtraq_id(56183);
  script_xref(name:"CERT", value:"225404");

  script_name(english:"HP/H3C and Huawei SNMP User Data Information Disclosure");
  script_summary(english:"Tries to enumerate the list of users");

  script_set_attribute(attribute:"synopsis", value:
"The remote networking device has an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host allows SNMP read-only access to either h3c-user.mib or
hh3c-user.mib.  These MIBs contain information such as usernames,
passwords, and user privileges.  A remote attacker with a valid
read-only community string could exploit this to enumerate usernames and
passwords, which could lead to administrative access to the device.");
  # http://grutztopia.jingojango.net/2012/10/hph3c-and-huawei-snmp-weak-access-to.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4b8d1ca");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c03515685
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3459f50");
  script_set_attribute(attribute:"solution", value:
"For HP devices, install the appropriate software update to fix this
issue.  If an update is not available, use one of the workarounds listed
in the referenced advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3268");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SNMP");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("snmp_settings.nasl", "snmp_sysDesc.nasl");
  script_require_keys("SNMP/community", "SNMP/sysDesc");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

sysdesc = get_kb_item_or_exit("SNMP/sysDesc");
if (sysdesc !~ 'H3C|Huawei')
  audit(AUDIT_HOST_NOT, 'a H3C or Huawei device');

community = get_kb_item_or_exit("SNMP/community");
port = get_kb_item("SNMP/port");
if (!port) port = 161;

if (!get_udp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, 'UDP');

oids = make_list(
  '1.3.6.1.4.1.2011.10.2.12.1.1.1.1', # h3cUserName (old)
  '1.3.6.1.4.1.25506.2.12.1.1.1.1'    # hh3cUserName (new)
);

foreach oid (oids)
{
  soc = open_sock_udp(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port, 'UDP');
  
  users = scan_snmp_string(socket:soc, community:community, oid:oid);
  close(soc);
  
  if (strlen(users))
  {
    if (report_verbosity > 0)
    {
      report = '\nNessus was able to get a list of users :\n\n' + users;
      security_hole(port:port, extra:report, protocol:"udp");
    }
    else security_hole(port:port, protocol:"udp");

    exit(0);
  }
}

audit(AUDIT_HOST_NOT, 'affected');

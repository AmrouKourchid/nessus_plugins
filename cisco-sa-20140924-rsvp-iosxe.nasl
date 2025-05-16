#TRUSTED 2ce2c875561bad9b4f6e9a272a932be19e3f9b845f4ebd9b8df75016ad863e980f3cf2a4eb2215506dfc5aaa6f226bd5e2d665067688130463735eb4098d084f37c400d6a02191c923519f7f064e0cfec1fb6fda20e9deba9704fd57c654cfcd5729919fbcc13094a6adf55d8918b40db0cc2eacd53c0c6365afde8c30a1c0e60244837bd3f12a3fba69ffc7d6027bf5ca56d61b09e479f860eaf8d96a667374b4b6ca3a51dd4cf64d33c43573ee59018759bb4c391cc4c5b4826e31a9106b12bdcadabaaaca00ac8ed0f58298424af742de9258c7c67ba9e8f04c0415bf8d814c86e46ef151968047686f8dd38b3c14ce40295a7ffd96e05aadd5078ae877ed3ac7300fbc8bc4339915667179678530bbed8aa80bf03568504503b09ed7444d59453e7acd47c87023091a4531bfd6788b94d3362fcfd5da7a08c1f3ceec9964cb02fa5aa9a3ea6b42b2962d30f18f62a3917e787e448bdc726c04fe4c6930a122c70c3d9252510478a31766cf54be18c8db910e5267a8e5b106f1a93b572bdabf5254417290049aff39ca5df090521b402915031d2ba89ece575abd5d08c5a99a0c073fd521d5e8f7776e29fe623d4e6c534c836fa44df2c77cae6941aea74b2164ec6e72294630e446aea086747f0a2d8dd9a98a225f4160605deb396e0a984168d997ef951d50fcc2cb7e4a0e3929ce35bf77a52b1dcbccfbccf18ea3a151
#TRUST-RSA-SHA256 2bfdba0a17f02e14afa499e525f2a02e55bbd0eb5d894997e998205e99eaa6cfbc65e56446cd2acc4b288606bb2ae59355517198986c6f947e4e1006c29f43773a83e97afc4bc9a1d6984a5ec4c0ee376dfc1230a99efd1bf76d2300e8ff107354e4d6127c18fe9bae9e7c46f98458612b3ba539a799247ff45b6616270ca2f8d72f0c720e4014b871ad66e244ceecc917810e0f5edfd4ca9c54ebe30bc8560867e6cea349ac708444b325120bd0f8cfcbad9ade4ca3fedbd79e4e8f17cac0687de20d58905d3bcb8c66a040dd2a0448951d7530629294cc0a9faac6646ce4896b83bfcf3ab7ed0ea073249838253491955e988484a939b308bbc1fa37b23961ca7438000591a9f4f475a5f834cdea3ecc93aa4008a822c8351ec0c4de7d495bba61f0e4dadcee952867ae998fd6c7945831c790c795ebe6e623c8eee2cc4c49ffba087363d9654dbea882230e7fc3b620e8a942a923d3cd9e802712349b2e99c860f923dfd73159cc1afa46dff7b500b7e4a3ce3a42f276040f64d317447519254b95e74ae6cd8e0d9c0c2ddcf4cfff9f9f96baab24b3c4e98ddde62a0edf335274a71b4db6c2eac199f336787c45fce94e922fc78c5c3156795d5bfcc7248ce0613543b314c53f9ee34d66aa249ee53f700f2a16c44c57606db776c8eeda02efddd140b34e9fa3d920fa0092c13c9680e2438b65d454008aa51e2b68a6a90c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78034);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3354");
  script_bugtraq_id(70131);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui11547");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-rsvp");

  script_name(english:"Cisco IOS XE Software RSVP DoS (cisco-sa-20140924-rsvp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Resource Reservation Protocol (RSVP)
implementation due to improper handling of RSVP packets. A remote
attacker can exploit this issue by sending specially crafted RSVP
packets to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39016c7b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35621");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCui11547");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-rsvp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCui11547";
fixed_ver = NULL;

if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-3]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[01]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-2]SG$"
)
  fixed_ver = "3.4.4SG";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver == "3.10.0S"
)
  fixed_ver = "3.10.4S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# RSVP check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:ip rsvp bandwidth|mpls traffic-eng tunnel)", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because RSVP is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));

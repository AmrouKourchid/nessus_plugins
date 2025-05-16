#TRUSTED 9b7890b5b099e97bb2a171d9e9ed0f75304e7d8727f2074503072a506f227c618452018d5c2ace88e001e3bac819176d2999129c151bafb61d5ebbb0755a94c71b72c5b99c46d4b5be681c77ce3a4feff93742f5fe7d57d216b5cd58a2f4f9b8efd638895ff71e51228a829b138e9715b6f990fb960e4e672439c61ee2190ad19e24318673b26fbd687d2b1644849bcb4f3404f927f166bb1bb755d8b6bb1b2e998e928a6e0f5e0ec7aa92e46db334cc1eedee014272da696a7f48249fb661e23c006b7b8da424507954648f166655c7d3276c33a6c086403d29a35c0cfae834e47de074d4d29f141ad187e6471c0c028d67d6a7490500a544e3f53e6089ff31817a0b2987a60057e735a709eda56ef23d6df3a115b388af1f18826ce217f5331273b95ec3755fea58eab1dade7d5d6d7b60876d63e6d156657af5f30ed586fb2f8ff51dbc43e6eff121d6d3b8881e25a0a7ddd50142d2ea8be7dd25193f110961c5a594a54359b8cb83c1b762011768082725d4cdf77b191bfac4099cceeae4c8de63cc7695bc7cc9111b2a0a9b33cac81bf09fc7a34cb989ec2b62487eab8aa96ad5627225e370069c78772e974e4b68891eabcf55e4f697120cfe7f0e7aaf174c48f12779a77bcc28494bf185e7962eb00ebf6c3292d3e38ff1c30ca9ac8a4f3f08701f0997fcdd39a0198d7a0b1332edf840d37784a14eaa5abae9256123
#TRUST-RSA-SHA256 7d3b2cc80c21a101956386e95bf188b1d6ed010c707040f737574105f4236bec4c2c9947ac104a5043aac8cececaaae36ea36cfc2223d50d63cac2ae154c8953954f9e2e7cb3b284f022786877399357cd7f39b99f88c7a15081136e09e85ca012467f275529e365f2811ace0dad43ea65cc1c039f7799484d63932ffd84401bde44d9c88787d2b3b5966c96b2f7b4056f97135697a1301e565f1933fa884b66cbd319cc04e64d2ca270d6227adca115ae0863d1b7b21a3c7915289d68d621e016d6692e3ee41abea7e4c90b0d39f6560ae864155e5c7003beee8d269e976a1ba7d70d6a7977808b99290acc784d43364d6851fd56fc32d3c762f7f87db0c414af6b5b9dee2b8728f4cd0cc75df26613699cf071754e633cb1d61490e77bec9fedc445410e79b679f32275105946a2146b57dad806bf38c337f62651e8138556c82b604eaaf5535eeb7e966b8e03a84f848af25183f01fa73bda46e81b98c00f246fac608135488de919d2fcf6dbf8ed44b6925434ca80f24247ab2ebb43f37a9aed0a97145663053f6d711af89b1597f355c0c25ab16d671b83b813254868ecd7d4197125e06f9005ac07566747f290ccb97719c4b8886ab7456cd69a11023dfbcfcefc0d4ef01ce73d369edca84841360374dc3ce599d1d11158c347b6f2a55991235e9df4610adbe2b33d83f9329d68fa6b8cb9bab8392f6dd4e357081d46
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39766);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5339",
    "CVE-2008-5340",
    "CVE-2008-5341",
    "CVE-2008-5342",
    "CVE-2008-5343",
    "CVE-2008-5344",
    "CVE-2008-5345",
    "CVE-2008-5346",
    "CVE-2008-5348",
    "CVE-2008-5349",
    "CVE-2008-5350",
    "CVE-2008-5351",
    "CVE-2008-5352",
    "CVE-2008-5353",
    "CVE-2008-5354",
    "CVE-2008-5356",
    "CVE-2008-5357",
    "CVE-2008-5359",
    "CVE-2008-5360",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1107"
  );
  script_bugtraq_id(32892, 34240);

  script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 9");
  script_summary(english:"Check for Java Release 9 on Mac OS X 10.4");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X older than release 9.

The remote version of this software contains several security
vulnerabilities.  A remote attacker could exploit these issues to
bypass security restrictions, disclose sensitive information, cause a
denial of service, or escalate privileges.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3633"
  );
  #http://lists.apple.com/archives/Security-announce/2009/Jun/msg00004.html
  script_set_attribute( attribute:"see_also", value:"http://www.nessus.org/u?39431345");
  script_set_attribute( attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1096");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(0);
    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }

  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);


# Mac OS X 10.4.11 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 8\.11\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(0);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 11.9.0.
  if (
    ver[0] < 11 ||
    (ver[0] == 11 && ver[1] < 9)
  ) security_hole(0);
}

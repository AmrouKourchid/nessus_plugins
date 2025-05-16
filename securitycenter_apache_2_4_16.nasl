#TRUSTED 254fffe20992434a52e9fa427a334a5ffcd298e7f9d5d52f1524e35026904192476034b3dd4ed8fbc145760bad59ece7c75f7614ddf4eee4468c68d2bc4d32550543a643d57d680da2184728e451404134cd5a19d96b626a4ae696191967a2a5090a2bbb2ad35c576ae6a0a8678110e37b5677c8d9b4c6bc2e2cd366ce4e99181e7df0e6775df75bb777c19dfca356ea1f68690e55d0c3a09c076e1ec645b3a700a6cd5907b032106b3a7c58121810e129f8d9bfed36abefcbd7f44b9fcbed08f297bbd68a581064ca33208a0296f34dc7297ad3c7bdcde009fd5ea13733171bc347d31f5345b0ef3504dbd989f261836697ce44118903642275dc219077d7083ef1d9ece6e0302e02a606f8df231b5d3a2b6f1b8c3b3fb47c18580874259b8761e55583586d61bffae7fada330c73c8eb833a00a27c6d93f03744e692fc61d61a47eb36c9f8b5fd6636b565563022cc40e436b19cd322609cd5a1e443a55862db9c068e4b6fecc0f898675d48fadf06fe8a67377e74ebd3b3c42d7574c4159dfecb06795f246ea8cbadc4fb59d64fd85a1b9d83e69762040a70ef33fd46a433fd5ad4c8d54fe0f066f95dd83b47adb8855880252814f46deaa1af1055441df47e9d3474c1f7ca180cf41f2756484799418f7aee39a2e31b8e9691ed939774c16f893550432bd572467ddc9eb10faa35fbf4615cf6deede6f76ec6140db91cc6
#TRUST-RSA-SHA256 614cd2ac17612c2f8ca9b59296e7c247cc2e87b82b51e062821528e33ceb5c4106ff4bfa2b7b65fd86aabc9b93eacc531e5f2553294a5ddb3f2ef05f1dfeddf78fed899d90cea392d58e33b123d4ce2f1046b781088f74c1ef6ab7e2e0e8bfe8b7e7787617321127b9a58207481183d01ef70b814a32603d6c3116a18e3a99f99af32105e1dea2d6a52bc36d06a671f806c943108bf48e06b7895ff4b879d4a165d8ac8c25444e6149625be8487c00c774025a37f88e60a855264fceabafdc436c488ddecee95600df673cdaa7522b766ff92610a0762835a43215088287ce667edc7204c9fd6d84c6957b09093b15ab01ef222efc5ceb16cf17b060df03bbebaaec4ff406dde8526ba5fe5d618fd6e625690447231a2e2989de66c6bec1bb187c61fd9eeb56686279ea26f5b2d8e4ae1fc548978270e8fd3d2e18297348fb6a6146b06f7a04c73fd6081ea87d8a2a84edcf745918930824e751490c2ba5b1c16d70a2114f15c6bdb22fae5d34f47b7b3dd4b8f2e3e8a9c43adba525348a2f1bc117b46707b85c99d210f6ef06a1481c2f07a9a7c94f7578ab6bd87734baf375efc97a554f24033f76d99d070151f2c95c002b825457dac09c4d08d657ee58742820c67438ab8d1e30656cab0f6fab4bb13e6aa7c535d5c4ec32ed7f6836accf3450a36dceb2d93de57933f5c6fea5afbca798b24141221a730a29bb06be3d26
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85628);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-3183", "CVE-2015-3185");
  script_bugtraq_id(75963, 75965);

  script_name(english:"Tenable SecurityCenter Multiple Apache Vulnerabilities (TNS-2015-11)");
  script_summary(english:"Checks the version of Apache in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
contains a bundled version of Apache HTTP Server prior to 2.4.16. It
is, therefore, affected by the following vulnerabilities :

  - A flaw exists in the chunked transfer coding
    implementation in http_filters.c. due to a failure to
    properly parse chunk headers when handling large
    chunk-size values and invalid chunk-extension
    characters. A remote attacker can exploit this, via a
    crafted request, to carry out HTTP request smuggling,
    potentially resulting in cache poisoning or the
    hijacking of credentials. (CVE-2015-3183)

  - A security bypass vulnerability exists due to a failure
    in the ap_some_auth_required() function in request.c to
    consider that a Require directive may be associated with
    an authorization setting instead of an authentication
    setting. A remote attacker can exploit this, by
    leveraging the presence of a module that relies on the
    2.2 API behavior, to bypass intended access restrictions
    under certain circumstances.
    (CVE-2015-3185)

Note that the 4.x version of SecurityCenter is impacted only by
CVE-2015-3183. The 5.x version is impacted by both CVE-2015-3183 and
CVE-2015-3185");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-11");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement2.2.html");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement2.4.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch for version 4.7.1 / 4.8.2 as referenced in
the vendor advisory. Alternatively, upgrade to Tenable SecurityCenter
version 5.0.2.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_keys("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


enable_ssh_wrappers();

if (! get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

sc_ver = get_kb_item("Host/SecurityCenter/Version");

port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
# No patches for SC 4.6
if (! preg(pattern:"^(4\.[678]|5)\.", string:sc_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Depending on the version of SC, the path and fix differ.
sc_path = "";
fix = "";

if (sc_ver =~ "^4\.")
{
  fix = "2.2.31";
  sc_path = "sc4";
}
else if (sc_ver =~ "^5\.")
{
  fix = "2.4.16";
  sc_path = "sc";
}

# Establish running of local commands
if (islocalhost())
{
  if (! defined_func("pread"))
    audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g)
    audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

line = info_send_cmd(cmd:"/opt/" + sc_path + "/support/bin/httpd -v");
if (info_t == INFO_SSH) ssh_close_connection();

if (!line)
  audit(AUDIT_UNKNOWN_APP_VER, "Apache (bundled with SecurityCenter)");

pattern = "Server version: Apache/([0-9.]+) ";
match = pregmatch(pattern:pattern, string:line);

if (isnull(match))
  audit(AUDIT_UNKNOWN_APP_VER, "Apache (bundled with SecurityCenter)");

version = match[1];

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version        : ' + sc_ver +
    '\n  SecurityCenter Apache version : ' + version +
    '\n  Fixed Apache version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Apache (bundled with SecurityCenter)", version);

#TRUSTED 9e044641fd1edc2da54dee85151968ee0006a98796703597ac14f02219422421e16fb7f4de38478c9b1aaf967281c7833c833453ab5863ce79f32c8c098ec5fa77fcfd744492631967f360cd76303cb0a600e843330e72f3c028903d7523e483170591ac1a5db52399927147e410b3550355676f402dc2b083c7c896391da8f41d9d4e9dc4f4de2db683d2b0eb29f8eabb20de7286b98f2967bb8612dd99e543ccd67d11bf1ab11f2bf67f3c11d58555b3eba248c3dc65daac8027cbc1dafe4e35ebd8795368422f88db67f3051da2f616882fd9cdae3607d604f90ed3436f7b9c83ed5c2e6b41b255a66dd453222c977c4830106127ec3f0b1913482ca47aa598e36d1f4a66fd27bb1f658c57bbfbacae673dd55decdbf44d80021ad85cbbf25b19823c46454e090a75104880f4de22774d05a825fd0eb0c1a53e23d6cd02addbc3411cb011f5c241a718bfc352ec29cd7c517f35be54cc38edae2e98ecddfeb3f5744554ae7d6f7bcfaf995b3e1fcbc6ef41967c562d8b5b78239c580faf7b35bd1eb5757ac1c7655719065d81cdf6b42119cd4bf15c470e660c51b2b690f950df8f80625e6e28141a2b858d939d427b4216d82d5c44fb97facdd996fd10910eb16f9047aafe573ccef31e157f55ad236c8aee08916b6d11f2744d6a8866dc6d220c33edd619b7c276df2be354ac6f7e1327a3c48d330f6b3cd217c5cf9d94
#TRUST-RSA-SHA256 5130086a717a6c02aedf398bea3f610bbfc7d0c3e0d18e37640d9723faa6e31787a9fc87e837980bb30137f141aae788ee98619fe47bc67fd617865b00113711293ca4fd94cfa096ac4df3da7361370c21b30a90fddd0203f546107c36191feb0c0e4f813d0e7e51dc001c802192cecb8d883852379823eeacd09d1033d753db5325a178a921f653b623b27e913114f4a6868493c8a30c8e1de151f999b8ba3793ff5532bc665f22c38afce799f70df8d7b6c7f7fe387cc2198b6821d1c9ad8a85458d53f068ff7bb7ea352be0aad27c30af6dd2775bad2311f1085d3ae4a33c3d6b68897763e56e47fdf5e1d0ebb8c9685ae405fd081af6545bf9824561b1094b74fe8f307f5ae4c2929b70f354e8740d41ff91ac15e4261895b225ca182251b6ab60906e0ade67c67f72707cb387a70830c5d9e8f0f4f1f23fb69d5e8f6f7fd7b9863b94d7978229f0c10fe82c3e9ff15bd3f187c27d50f0a116111c6bee66ce731df345f006d2f0f870ceedc04fd9ccda5b08a61a082d2e38416876b58ce4253ca64ec1cb8bfdaab600800167c11135d021a00aac44629fc1271609be759c155fea8ba57c48f761ec842e249a5672094e618f437586a185437054685279bbe1b2727ef2386ee47c2af99ee23dd5c212dcc6f8459064aa71d7da6e4d5a854148c07486020df60c1e57c06255e5bd948e78b4d68f049f7778557d031158d341
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85565);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-1793");
  script_bugtraq_id(75652);

  script_name(english:"Tenable SecurityCenter Alternative Certificate Validation Bypass Vulnerability (TNS-2015-08)");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by a certificate validation bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by a certificate validation bypass vulnerability in the
bundled OpenSSL library. The library is version 1.0.1n or later and
prior to 1.0.1p. It is, therefore, affected by a flaw in the
X509_verify_cert() function that is triggered when locating alternate
certificate chains in cases where the first attempt to build such a
chain fails. A remote attacker can exploit this to cause certain
certificate checks to be bypassed, resulting in an invalid certificate
being considered valid.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-08");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150709.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1793");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/local_checks_enabled");

  exit(0);
}

include("openssl_version.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


enable_ssh_wrappers();

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (! preg(pattern:"^(4\.[6-8]\.|5\.0\.[0-1])", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Establish running of local commands
if ( islocalhost() )
{
  if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

fixes = make_list("1.0.1p", "1.0.2d");
cutoffs = make_list("1.0.1n", "1.0.2b");
pattern = "OpenSSL (\d+(?:\.\d+)*(-beta\d+|[a-z]*))";

# Check version
line = info_send_cmd(cmd:"/opt/sc4/support/bin/openssl version");
if (!line) line = info_send_cmd(cmd:"/opt/sc/support/bin/openssl version");
if (info_t == INFO_SSH) ssh_close_connection();

if (!line) audit(AUDIT_UNKNOWN_APP_VER, "OpenSSL (within SecurityCenter)");
match = pregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, line);
version = match[1];

fix = NULL;

for ( i=0; i<2; i++)
{
  if (
    openssl_ver_cmp(ver:version, fix:fixes[i], same_branch:TRUE, is_min_check:FALSE) < 0 &&
    openssl_ver_cmp(ver:version, fix:cutoffs[i], same_branch:TRUE, is_min_check:FALSE) >= 0
  )
  {
    fix = fixes[i];
    break;
  }
}

if (!isnull(fix))
{
  report = '\n' +
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter OpenSSL version : ' + version +
    '\n  Fixed OpenSSL version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OpenSSL (within SecurityCenter)", version);

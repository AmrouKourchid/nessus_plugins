#TRUSTED 8f349767c465bb134511cd995c41af9fbb115f99290d85e60e6d322e2d218a3ba06fd02b344175bc4ce398ee9dd045064a5ff61bd7de7f80fc941edc21a864595f21a8dc2517fc3c6fceb5fa090d7d7d6993c8aa916a410752bb1e376c639936b66126e7d2de1e5caf233773af54797238afd7393230febb6200c9d8ff819f3691f161e6d18a34eb230e4fab042d18e70305aff288d3349fed4b533fdaebb6bf097e5679f97a47a2b0aea07063c16806b1a762aadd947824e7fb240612c8f93b6587f6972b912b4118268af6d54c18ff02cec6ad3a573d4bda4eb51798a6fff652083054fd6ea22c7ac387b752c4dc70b8ae8a4d8dd62e9c23241a18b2dca2d27be04eff9282a5bb4cfce96b385cd2eb996d04720044eea0b8156285950d07efa50cb73e1a316b875bbac8b93b32afd8ca5cbc700849af71ca85c704c778e94e470b069419c20ff1e25e3cd0fa6859203220ddeb1b2187830a021f1d794478def295e79e8fd8e2903c4028ec1fa8f8398974b4ee64ab85f7de01f3a6210a4ecdd59867e673f2e04b4cccb3c4419be1b481d720c065299d3b9b905cab4ff85ae42bb43d018df389ff259ae87dfc83234595537a6603dd1ccb6d5d6c63750acb1407e1ff3ab67c426d1de204b80af82ceb20979057188b97147027766018a5e440cd9bafbec2d8484b11de07f4fbb020409d809a8ff8eb88fd96cc2daea3fd18a1
#TRUST-RSA-SHA256 0f61b4fbcccb399cf3d5b9b72d526b81602b1ee2dfee85f7277ec3fff67fd0240b1b4955eb4d92ec1c9a8142d5868b9437fa1c28ffef6ae21a46bbf5ce0fd6c77d4b967f6b259810005f2ca70a0ede0d3226b238b7e7a1a706e21fe1d50a40f7e135d8b1676c7707696a83ba9e23ff14d71eff76140a75bbc0aade5f2bb29332406b1b228f615f2a136df25df13951bb456180b78f329da893aa8acd3ff15c350e700425d1650724341c7ee4d8b797d8f9bede4a9fc37d665f74cb8cfaf43415bc6da86fb7b33f9ea7fde8ec90077e8716ec1b05330bd6405a45dd4a660eb47673ca1f26737e67ec82a2b0b69b972debff7d73b53db3131f4ed144fea31267ddb6aca8d576f63b0357ac0a1c4162f177409576344477ddada7adc0e364ab5c3e307650689a13bd560d4e5f6afaaed37def3e75e6de080d01f666dc2465d954ac6b6b9a127ba59683edb5a3a93ec1393528f1353e7f1e239b51fd9f3f825c5c1ae64b752a991d9b0bec40bd81d52a73bed8eb1fdbd26347ff3b8aae7479d2f37e8b1a612be9f721cc866958e97b71cb4c0fa053f0e54cca3879b7d1597cb63756a0901a2886901d3cb785b80fefb7592987782ad851b4263f8a41610003c60a911582065adde5ee6d7380951b9e6f1413051bb06e66b8705778c9526b6013134a40a186af4594fdd10a508cd01b9c12631b28cc1eb1a9661469adf8111baa58a2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97575);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");


  script_name(english:"Tenable SecurityCenter 5.4.x <= 5.4.3 PHP Object Deserialization Remote File Deletion (TNS-2017-05)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a PHP
object deserialization vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is affected by a PHP object deserialization
vulnerability in the PluginParser.php script. An authenticated, remote
attacker can exploit this, by uploading a specially crafted PHP
object, to delete arbitrary files on the remote host.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-05");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:'cvss_score_rationale', value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");
include("install_func.inc");


enable_ssh_wrappers();

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(version))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}
vuln = FALSE;

# Affects versions 5.4.0 - 5.4.3
if (version =~ "^5\.4\.[0-3]$")
{
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

  # Check version
  res = info_send_cmd(cmd:"cat /opt/sc/src/lib/PluginParser.php");
  if (info_t == INFO_SSH) ssh_close_connection();

  if (! res || "class PluginParser" >!< res) exit(1, "The command 'cat /opt/sc/src/lib/PluginParser.php' failed.");

  if ('$errorText = "Possible exploit attempt intercepted' >!< res)
  {
    vuln = TRUE;
    fix = "Apply the patch referenced in the TNS-2017-05 advisory.";
  }
}

if (vuln)
{
  report =
    '\n  Installed version  : ' + version +
    '\n  Fixed version      : ' + fix + '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);

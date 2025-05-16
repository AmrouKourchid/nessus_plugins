#TRUSTED 35516ccb293a2c78abfeeb6868425619f58a5e83ec4cea1b987469329c532dc4652c2a37c6171b2a0b0c239915bf26d2877d00637b1bc90579384a57ed573a83ebbd0aeb1f87c0dccecf36028616eb5e6941216a3936d5cf3bd46a31dd4d928f9ccbe048ed36718701949fc3fb82d40e7a0977290cbb3a26b2947e6232c3ece4826df9e644cdbc07e31afc41bfee37c0e8c94cb186296097ce999172f72755abd71aeba8da13d6bf27581308e2f6294b43eb149079f9218deaa43b5547ab96baa282fec8bcddaf0bb51c6d37f063cae9ac82404f60e7c80e416dd2256c523991af89f28f1b188c49f2d4127753e3519b3662921e1b8d626fdd4d1f2015d35280940faca35782d08f86c19bed0c502117f849984bbd6dcaeff0b423202a8c21d49f64d16718fa4eeab0fae9b0163de98b6e6ef30c65beb544a280139e2ba87141a3b9b9656410f28653e33af89c7bf7ff62b181af04f7b30c1921a73c2bcb453e8510762bc8ffd681826da884abd92faa45d9dd7570c0ba7072a14d0a5f277a03146db7ea4b12be12afd21a3ae6d662657cb404918412eeaba818bc022aebdc6454836b784b6c456176121e12558242f3dd4c86568eea4d4b4861b610f088ad5f87361eaa9a6d7d65024d9856040a1a37c4a6eda0f4a2fef906790111407c3262d88c6748917088073020b73052e1c03ab63104d331158d36b5edea15bcc8466a
#TRUST-RSA-SHA256 5e5334c84848708fb511ec27f573d775f907e04216d6e5872dd9a1ba27a76f7601a6e1cd4df05014d2967225abbf4815c5de243ec35e7b9609dc2be4a4954f29b172f077294ee6d98f1a190dd4d57274b30d4aadff0c8d2e7bd740f5504c811436974579d865c95c8747144a57af8bf09928c3e6e0acaf3e565e31f7a98c1464a6dd595c63ac2df6b46144a06c94ac05343789f55d4097aaa396b0c5fa975866f79ec395c89f65c24f15e8fa1360da83f5636fadc64a5ecc087d4dd3cfdc549704aee1da524c4a28a8e0ac5ec8669df859de2fd7a57865faa067b6934e0eef1ec9471c17faff924e5b2c33dd32f5cbde4b1748cbc0f52b48a5fe78e22727d7cc59b7038e6ffff5167a0f8bcc01fe9e745d58f1b5cb44e656c2a29b27370554b04e5eb9ae63ae3368f8222a321c364e3f260607f2611ddf132e5a8f0cf782e8390774f9d930bb955f63692aac283ad07a61f78e5645d6bb48d5c5f49df2f7cfdf906eef290f15de2ecae77e40d256b360b92e91b1e9debb2e4d00b2da513ab4f0e8fbdc35ffb848d7d83cf749d1e906cb9c6cfdd15a578898db43d1c9622a99d406a9aa4ecb7933d6afab1d68f53f08303645d9dc51e6ac9e8d9ce9c515e45a699de849b251451ea420149788bf9a9d362eb8654bfe5e487090c8cc4da8a8fe89017f0b0ec4fb3004f39bdaaea76fc2928396b0d4541932eee935f12f2d98924c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85183);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-4149", "CVE-2015-4150");

  script_name(english:"Tenable SecurityCenter < 5.0.1 Multiple RCE (TNS-2015-10)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is affected by multiple remote code execution
vulnerabilities :

  - A flaw exists due to improper sanitization of
    user-supplied files during upload functions. An
    authenticated, remote attacker can exploit this, by
    uploading a dashboard for another user, to execute
    arbitrary code when the server processes the file.

  - A flaw exists due to improper sanitization of
    user-supplied files during upload functions. An
    authenticated, remote attacker can exploit this, by
    uploading a custom plugin or custom passive plugin with
    a specially crafted archive file name, to execute
    arbitrary code when the server processes the file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 4.6.2.2 / 4.7.1 / 4.8.2 and
apply the appropriate patch referenced in the vendor advisory.
Alternatively, upgrade to version 5.0.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Affects versions 4.6.2.2, 4.7.0, 4.7.1, 4.8.0, 4.8.1, 4.8.2 and 5.0.0
if (version =~ "^4\.(6\.2\.2|7\.[01]|8\.[0-2])$")
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

  file = "/opt/sc4/src/tools/customPluginUpload.php";
  # Patched MD5 for /opt/sc4/src/tools/customPluginUpload.php
  if (version =~ "^4\.6") fix_md5 = '65bc765ae62d8127c012ec286cabc686'; 
  if (version =~ "^4\.7") fix_md5 = '65bc765ae62d8127c012ec286cabc686';
  if (version =~ "^4\.8") fix_md5 = '5784a4f1e87ab0feb32f82a4dfd84c9b';

  # Check version
  res = info_send_cmd(cmd:"md5sum " + file);
  if (info_t == INFO_SSH) ssh_close_connection();

  if (! res) exit(1, "The command 'md5sum "+file+"' failed.");

  if (res !~ '^[a-f0-9]{32}')
    exit(1, "Unable to obtain an MD5 hash for '"+file+"'.");

  if (fix_md5 >!< res)
  {
    vuln = TRUE;
    # 4.6.2.2
    if (version == "4.6.2.2")
      fix = "Apply the 4.6.2.2 patch referenced in the TNS-2015-10 advisory.";
    # 4.7.x
    if (version =~ "^4\.7")
    {
      if (version == "4.7.1")
        fix = "Apply the 4.7.1 patch referenced in the TNS-2015-10 advisory.";
      else
        fix = "Upgrade to version 4.7.1 and apply the 4.7.1 patch referenced in the TNS-2015-10 advisory.";
    }
    # 4.8.x
    if (version =~ "^4\.8")
    {
      if (version == "4.8.2")
        fix = "Apply the 4.8.2 patch referenced in the TNS-2015-10 advisory.";
      else
        fix = "Upgrade to version 4.8.2 and apply the 4.8.2 patch referenced in the TNS-2015-10 advisory.";
    }
  }
}
else if (version =~ "^5\.")
{

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 5 && ver[1] == 0 && ver[2] < 1)
  {
    vuln = TRUE;
    fix = "5.0.1";
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);

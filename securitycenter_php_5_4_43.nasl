#TRUSTED 7bac3758b30922e48de19bcc8c9123452347de13356d8aa5eff068d22c53adde058ff36882ab2d8550c3157c889fece3a2464f0554cd0b3910b0f567dd15a8e5a0aaaded87aab860d43e249997978e66e4e3fd9f85ac2a2a7885635c5166028b9de0d28b2f9f1e8a7d35648df10613691dce9b50843e96f2386aac2d8b350b6ce1ff0b0d54ae226ab0e65f667f6d703e718148fbcc3e02fcfa657912a9c449a9dc9938ebba30924d448cc9d6dc35a3ecd2cd02fb6ce78cdb5ce0a1dc8a916eaeb333bfa7e442d00c17b9248f68c97dcc3e43c7efc5403781bbbb7943e604b6189ea8459670c46d7eca311481e7937f73be09ed98f40f3ef944abcf8bd0df03d209dda7414c64643086c1726bd8231b5730f12c28e04aa0e3059ba26208e816717428d1829974268ff8bd4aa9e41dd59acd1bd1e1be12a54fa3e5136094a5ac01218ed95cbb07446ced15c745a1f3d0d64f9be424dc63837f4eaf213c12d7669ff0a53b3475817199ad5bf92c5dfe0850aa4989d217abf1ff827438be96e9a270c3a82072282c94efa441f607c551b052ae58c02aa0ae6a2913838bc954223c7165e61de1b0f26ee279ca0fa6302f752ea2708b18a13401458c7e283d0f8c203cdb0280de0caf84359d20f995ce06cd240a2fb3b92d180e42711166c610ed6f954b3ee77e9265afc12138fdd18071fc9785c6fac6f9c065c3ce47c999d08157e0
#TRUST-RSA-SHA256 7235c31c6d55381523fba53616ea8d8387e9067d90cbcca8d9ad5c79ccf1b66d2d5d88156e6e225656f332cbb237bd4db0e204acfaccc51e46f35b6325d1ca4e0f2dc67c2869b7e7373ebac80f63941eb136b90e1832e43b6de8de134489f7769146ef127b8e42f22c65a51d3bcd3f36c2dd6a15d04431426cd2c5abb8dc7aa5a88e9f435cefe66d954af215b7f96b3c752b73f7661551f90e54ca9f061b3fe665338cf90f9d8248e31eb9d39ca8307d6a7afc1a95fa18584d33d11e1582a3a2c7ed247ae2066a3c272f6d387034134035116eada8e10e0d7b188fdc8e100769c235c37e8e816cae1170076a32d04e40a64967c1e6206583b478c4e45d9e4a7c9a548e3104b4a077ef4d1a096eeea8a801879810d92fee6d25cdf8eb9f2258e24e624f87f2f63d91a6db0a47608de039a936fe45bce13aa18b29b3a7ee407c75d0bddd4d325aa062a8e1a517884eb2d9c50f750228e066ffae13689977f244740c7bf37bdbc2c6347913d635ae18f4ad80c3d332a97ec1755dd95b5a9764fbad4d88dfc754a43f595a8b3df94aa8caf1c9c0cbeec7cd3ac6fc9d509b2cee767c3777cebebf8596314ce86891f1cd235a3687847677075963e271108d41ee162a3392809ef52d026a2c4c54523fdd442e33301b1daa63c74ccee1fabecce03cd9c7f32d6876b49f2fdaa4800d771293af175328b8aa70296eea20820d84bede45
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89027);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");


  script_name(english:"Tenable SecurityCenter PHP Character Handling (TNS-2015-09)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by a character handling
vulnerability in the bundled version of PHP.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host contains a
bundled version of PHP that is prior to 5.4.43. It is, therefore,
affected by an exclamation mark character handling issue in the
escapeshellcmd() and escapeshellarg() PHP functions. A remote attacker
can exploit this to substitute environment variables.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-09");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=69768");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.4.43");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.27");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.11");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch as referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:'cvss_score_rationale', value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
# Affected: SecurityCenter 4.8, 4.8.1, 5.0.0.1
if (sc_ver !~ "^(4\.8($|\.)|5\.0\.0\.)") audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

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

line = info_send_cmd(cmd:"/opt/sc4/support/bin/php -v");
if (empty_or_null(line)) line = info_send_cmd(cmd:"/opt/sc/support/bin/php -v");
if (empty_or_null(line))
{
  if(info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");
}

if(info_t == INFO_SSH) ssh_close_connection();

pattern = "PHP ([0-9.]+) ";
match = pregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");
version = match[1];

if (version =~ "^5\.4\.") fix = "5.4.43";
else if (version =~ "^5\.5\.") fix = "5.5.27";
else if (version =~ "^5\.6\.") fix = "5.6.11";
else fix = "5.4.43"; # default to known php release branch used in advisory

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version     : ' + sc_ver +
    '\n  SecurityCenter PHP version : ' + version +
    '\n  Fixed PHP version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "PHP (within SecurityCenter)", version);

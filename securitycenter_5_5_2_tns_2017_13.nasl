#TRUSTED 61a62e5a175c29ae6bb19da21b39daea05200a06ffbcebb5478ce91177ff5ad75e5f88a21755f48db6b19f9d0893fd65578d10543316f52a9c04fd3a578211c5cdefb250702c7330159fd0dfd724ea0e2312dc554c5cad859ae8d5da0cc91b81db14293bbb25b32a5d7ee5d550fb58921b9fb1f7d82ff1d18f83ab9dad4512c9e8a116fa69a08f9f2262cb427c720f30c7cb7770585b2407ebf55b0121cdaf76d075d62253e92b70adcf1934b02a09c1d886ba4f75efdb3ba272aec77af4cb15338cfd131b10fb904532a7d1634619f6cf413cf45c76db8349e748bc99a9838f802076d8ebd6a620e861200849269be4e5b3df51b44e54b0736f920f4f441935816eb116bec5056f95231cbc14d537624ffbc617217b265566d2eed9db0948077d03a93bbf7b628966524d2fae42ff74f283a3670d8c872a209fb372db9af1af377eb8bfd0eb85c8e2f4f3f8fc17087632a1382646480d9c3076ec938e4e025b2cfed686e65544fac522320cc7eea377f1b3ea847e985cad0ae636f2e6046cf62dc656ff2d6d103ff0964d4c6385e2db2ad3a1e38549ed95f6dad7fd4b8f036eb4a0d015aad7381a0cbdd7c907f8b3b109fd510c2dcb9773230f918b015aac124b4108f3f29158d5330931bb3f51eed8270643d55195d0dd3d0b384acf556b998f3c1be8c19adda63e8297e062567c186436986498250662401ca9356f7b8c59
#TRUST-RSA-SHA256 99d696ffa5a520ced594717a107dfebbbf01a71252917d66e2377d45346827116c12972c9dc83591ec36ed9d39113661eef16c906439329fc3f106496c601e9ea12b4dadc628bdf5b0c4b4882c8313528cd193a5c64c1bbca2e1ff2f165a6a054ed35ce8ccecb99c150f6fd8cd44f55cefe4975d51e572ccf85a59a0066f4e3dcbf65be425cfc76810cb0795f86a62671a797ef93aee78d375ff5199c4dbed2ccd89a78c7c247f86edf75eb36f2c47bdc50892d52677b021615d4d1b19374f0944307f9432a8a79117b90ecc1fd383964a35757ee60fe783c1a4ce4a39e2eb97b82b41d7a513eaf9d2185690ae5b3474481038fda7683e025a3633d5def8c4e655f6302906ee59b7d44a358bd9e9fbb6323c8ca3e303df8f88475fbd9862bb5aa7c021df1622af4ee3460e146385b157268bb3f3af903cbab4695f4ff699c6611ee4c2b821636bd62e1374aa778c728b8920ed653d58ef88e1c932481c5ab255e58a7e7e33fbbdd8514158ce5668e9817ce21b6c3186a2cb8474a35262925221711b7d218ae2e504e10f92b8550082434e6f547f327c77f81e99b9adb79860a4e0babeb19422bf6e06e1323c743806c226c632594a36157fa552c0a5a6315a6de779a8609e7e594f6d6f1f3a890dce590e3933c7abd00fb044e384ead1d9c092a91bfef5cec614a4a4d26aa394d5aabaebbdc731d35357ba81b4154fe1d2d8f1
#
# (C) Tenable Network Security, Inc.


include("compat.inc");

if (description)
{
  script_id(104361);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2017-11508");

  script_name(english:"Tenable SecurityCenter 5.5.0 <= 5.5.2 SQLi (TNS-2017-13)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by 
a SQL injection flaw.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter
application installed on the remote host is affected by a SQL 
injection flaw.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-13");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory or 
upgrade to Tenable SecurityCenter version 5.6.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

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

# Affects versions 5.5.0 - 5.5.2
if (version =~ "^5\.5\.[0-2]$")
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

    # Check scan.php file if it contains the patched lines
    res = info_send_cmd(cmd:"cat /opt/sc/src/tools/scan.php");
    if (info_t == INFO_SSH) ssh_close_connection();
    if (! res || 'setStatus(SCAN_PREPARING);' >!< res) exit(1, "The command 'cat /opt/sc/src/tools/scan.php' failed.");
    if ('$stmt->execute($sqlParams[$sqlIndex]);' >!< res)
    {
      vuln = TRUE;
      fix = "Apply the patch referenced in the TNS-2017-13 advisory or upgrade to version 5.6.0 or later.";
    }
}

if (vuln)
{
    report =
          '\n  Installed version  : ' + version +
              '\n  Fixed version      : ' + fix + '\n';
      security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);


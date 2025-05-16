#TRUSTED 62420edf382bad298ffb8f50015a048349a780d4a70ee2f9be04543c2fa3cf4630f1548973ed5ca944b2475f704c5756a649c5f5ef8a0ee3154cdddd49f53b0112cb4bb42a78de99b6e68e30ce22ed23b6a22923581feed86d757ef1eada2705691d2ab518e262c1c6bcfa80ce16df758b7ea413fb7309a39e901265a6cf8b81fa66913d89df7de07bab33a1624ca7a34e9214861efefee09fde62e3754125f323442053bbb7790f3cbf0b85bc05cfc16c63c75b38e35d0600bdd3f85f304eb5f2dc60ff33074b4d3dca1766bced0c4512a93fc6021a1f7cc405679d305147d198b0400d4971431c740300ca20c9260b8f27597baeda2863bc478977b8ad7102461fabb1e3f4870f739e9216ff20520605c24c99aef8bce7c09bf9ef6547225baced93cd07eadb26ca9842f7354592f656994965add169bb1b30153046ca7c25802f15cfeab38a483a33b8aa2b13139fa553f79171ed05e4434eea4662422f1f13535372002da751c673cfaf6d68957a7a802bd33afbd2650e6149acb6b7bf0358a55ff9fa99aa2bdc67f2a7db3a479c73e9632e7822e1dcb99152130bc5bdc863dc2a711f6a35dd171ff64709389810a59c6e9362f9793f78a4c246cfa3cd8f274ede0600734c044d3a75801d8cd9cad98d8b2f643a0fdbeff2c37a2e9e87c91af051a3fa26d2c56ee563238dd1a9966fbd3cd3a46c6b61242adb180e7cdfa8
#TRUST-RSA-SHA256 494e822e1a8745da2032b7db3ea18b3e728f03f036a3433332d5f194f060d561655f67474b509fb226958e5681db5eca5e136c2c4456025d07d5e3e787361ceda1dab7456735a1845d47caed3a2fbb8e4a8375ca60fc46e3eb61d33262001d49539231dc36c76cdb4f94e2a6bf52a03e26ebce7ce2da6a5a5379ebab913fc9196a27ea261e05a6a3ac7436796ab4f9039339b1026f203b7f88b3e8e46349c4a8f36b18cb73b54661779ad091f72fc16543bcfd5cf6529124c3c5ce650d93fdd1c300b015829d4f39fb5f900c8c33870764b9422e18157651a913add290b1f0f112b13547a874332c4c4ab5f6103ae65be0214fd98386a5eda8c6108a3b4ead7569851f0f6bd0ce7848b6f56b34b929a655b949d2f7e5a57bab2f1b4108e74161a82a8c6cee63f0726d998bde14472661b0568acaf145649086b5b3f648ab6245f2bc24fa4e888a53d6c0c81ef7941b6543c49130919045d8d3ccae7bcfc2b3d2568e8402a4b0409dd54f6ee2786c327e0d2123f8d70d6f82409d1616171c4336e3780fb99c9fa571cce3555543fd4ac9647fd540d951c8b61fa78b1acd9ac14acfeab0f8e40b2065a103ab7465821534031b91f1dcb8242c01de370da2e8ef82c5e53dc3232e0d5128ca5916c59f9ebbe9dff2de159d729e935c6d4aa6bdad182b2b2f4f720e70021f82434bc83b105df00d4f7bd90820fe12a926983b790b6f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80194);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2014-3412");
  script_bugtraq_id(67454);

  script_name(english:"Juniper Junos Space < 13.3R1.8 Arbitrary Command Execution (JSA10626)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 13.3R1.8. It is, therefore, affected by a remote
command execution vulnerability that exists when the firewall is
disabled. This could allow a remote attacker to execute arbitrary
commands with root privileges.

Note that the firewall is enabled by default on Junos Space.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10626");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Space 13.3R1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Junos_Space/version", "Host/Junos_Space/release");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("junos.inc");
include("misc_func.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Junos_Space/release");
if (isnull(release) || "Junos Space" >!< release) audit(AUDIT_OS_NOT, "Juniper Junos Space");

ver = get_kb_item_or_exit('Host/Junos_Space/version');
if(_junos_space_ver_compare(ver:ver, fix:'13.3R1.8') >= 0)
  exit(0, 'Junos Space ' + ver + ' is not affected.');

if(report_paranoia < 2)
{
  if ( islocalhost() )
  {
    if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (! sock_g) exit(1, "ssh_open_connection() failed.");
    info_t = INFO_SSH;
  }

  cmd = 'service iptables status';
  buf = info_send_cmd(cmd:cmd);

  ssh_close_connection();

  if ("Firewall is not running" >< buf)
    security_report_v4(port:0, extra:get_report(ver:ver, fix:'13.3R1.8'), severity:SECURITY_HOLE);
  else if ("Table: filter" >< buf)
    exit(0, "The firewall is enabled on the remote host.");
  else
    exit(1, "Failed to determine whether the firewall is enabled on the remote host.");
}
else
{
  security_report_v4(port:0, extra:get_report(ver:ver, fix:'13.3R1.8'), severity:SECURITY_HOLE);
}


#TRUSTED 79d6eec8fa3271b6550895aba02632586fa553507777aee588e6856e32490c28f1e55b067d67eb76997f7d681e4cfbaf1df3d8c3c4428346839fc926ba1dc3c1307ec56fd7ebb75747e5b01877c56ca525da2ba9499fee790026e961a59567dc73ccd1c56717a18f85fd190b3ad6b822e73bdd6742043de65a597e413d4f5136d06a7aeeacd1a0bed5ad99c1df22b9a98858ab68a802e16020ed47d8cec716d739e76f6062d4e1ba29f1f2c7a3e8acc70c6c5a94c026e11f1549826e82ba4bcafead087d530e40c011b637ac2a66e4874eeb3807ba312d904b609eb6c43c46451aa46ac645bee2e878ed41026bb761ee6c029a5644612dc5712ef0fb65cd8d3d1bc61ef489182f705a3a8479012cfa2452c15fc9875f3bf1aef3e064a96a6b53f3727119807a89b737ae6f2cb10a5076b57f9e908d6c18b8cfbd9fa28f2de3f03046bfeb858dc7446a51d7936754961c3d78c3f5e03998247b14a1b65048154c636493ba751cc5c0427911b7dbe2ae47e5f565e53720a0aa5c8673146d45b16a238fa15df8a5f4764e6d75a4e61d18ada8455d70f4aa4c3184b04faca401e3d9b48adda7ca65b8e25a43ed5c873123c403858fd46515c0c4cad56acfb43b58720466fa236678902a98dc60bf64bae3e00fb99bcae4a77ebd61add63cabecebae07fe47f01a87000c26a0139e9fb3142783e9132055ab9f04ef1264fe6cd6db1d
#TRUST-RSA-SHA256 0b54c3a9759c1bb886ae3cb126302548f6dd092947775aac95349b5969ee1427b80935519f2f042e096faa8b391e68413bc2e1d416e5a774b1ba00d9153389c258f6b7623bf925b6cbf55424ee4b41cfe59e9ca6b06f1a394f1ce6e8e65f32b06ca3be1e5473044d49b7d0b24c49dbc39646dd090de72a55cb0b47a3025673b22f640db13011cc83ad1a8cd35cf5cb1c90bf243177a940b2f24c439c6dafbe7634b82cf2ed5a757e647fbd24d34e5884d8ba31c5b8115c060e52aa2234a3c7f9092e49ef1e5dd285cd143077ca22b39b934f8c95760d5bed08b1541fceae53421ca285e56b9bd37a09c0d49844c05bcf40c9847a9c9771c90a3cb487cb9c44be3d2ebd93d92eaaf3b59159820fe13d19ec17440c12b96ad35578cb5b8222ec5dc3bff1b920c9a3d0d01a2ea1a83794c422d9e5247891833812893866fd58ef8ec7dc3161a78df42f8ad410371a0aba5631424d559a798dd2439679a39e1c5e315ac3285778ac1e77897c95b877007537148a8db041b95826f0788a755547a411af7abdcc0d4a185fa0b8c25d551e0165c7e93d0f178c243719c1f9067079f5c9615d596e26fbcfe8a1418a5f2d4ef3315e4ac9453880a1d0bd4f2057c7f190f2ddbdeca0a66ed46731b8b74ec15fb3b8f7b5198bc543ac44c58c3baf5b087986c099626012f2180282e321ccfb80d7e38b6e83f743031097687cc5e8328acc07
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104498);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_bugtraq_id(101664);

  script_xref(name:"IAVB", value:"2017-B-0150-S");

  script_name(english:"Splunk Non-root Configuration Local Privilege Escalation");
  script_summary(english:"Checks the Splunk configuration.");


  script_set_attribute(attribute:"synopsis", value:
"Checks Splunk configuration on the host for a local privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Splunk install detected on the remote host is vulnerable to a non-root
configuration local privilege escalation vulnerability. Please refer the vendor
advisory for remediation actions.");

  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP3M");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate configuration changes listed in the vendor
advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score was calculated by vendor.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "process_on_port.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
servs = get_kb_list_or_exit("Host/Listeners/*");
uname = get_kb_item_or_exit("Host/uname");
process = '';
splunk_home = '';
running_user = '';
conf_owner = '';
etc_owner = '';
vulnerable = FALSE;

# This plugin only works on AIX and Linux
if ('Linux' >!< uname && 'AIX' >!< uname)
  exit(0, "The Splunk local privilege escalation check is not supported on the
remote OS at this time.");

# Find splunk service
foreach serv (servs)
{
  if (serv =~ '/splunkd')
  {
    process = serv;
    break;
  }
}

if (empty_or_null(process))
{
  exit(0, "The Splunk process was not detected on the remote host.");
}

enable_ssh_wrappers();

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

# get path
match = pregmatch(pattern:"^(.+)/[^/]+$", string:process);

if (!isnull(match) && !isnull(match[1]))
{
  splunk_home = match[1] - "/bin";
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "Unable to determine the Splunk home directory.");
}

# determine the running user
buf = info_send_cmd(cmd:"ps aux | grep -e '" + process + "' | grep -v 'grep'");
match = pregmatch(pattern:'^(.+?)\\s.*$', string:buf);

if (!isnull(match) && !isnull(match[1]))
{
  if('root' >!< match[1])
    running_user = match[1];
  else
  {
    if (info_t == INFO_SSH) ssh_close_connection();
    audit(AUDIT_OS_CONF_NOT_VULN, "Splunk");
  }
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "Unable to determine the Splunk user.");
}

# determine the owner of $SPLUNK_HOME
buf = info_send_cmd(cmd:"ls -ld " + splunk_home + " | awk '{ print $3 }'");
if (!isnull(buf))
{
  home_owner = strip(buf);
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "Unable to determine the owner of $SPLUNK_HOME.");
}

# determine the owner of $SPLUNK_HOME/etc
buf = info_send_cmd(cmd:"ls -ld " + splunk_home + "/etc | awk '{ print $3 }'");
if (!isnull(buf))
{
  etc_owner = strip(buf);
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "Unable to determine the owner of $SPLUNK_HOME/etc.");
}

# check running user vs owners of etc and home. only a configuration where
#  they are all the same is considered potentially vulnerable by the advisory
if (running_user != home_owner || running_user != etc_owner)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_OS_CONF_NOT_VULN, "Splunk");
}
else
{
  if ('Linux' >< uname)
  {
    buf = info_send_cmd(cmd:"cat /etc/rc.d/init.d/splunk | grep -E '^[^#]*splunk enable boot-start'");
    buf2 = info_send_cmd(cmd:"cat " + splunk_home + "/etc/splunk-launch.conf | grep -F 'SPLUNK_OS_USER='");
    #possible mitigation
    buf3 = info_send_cmd(cmd:"cat /etc/rc.d/init.d/splunk | grep -F 'su - '");
    if ((!isnull(buf) || !isnull(buf2)) && isnull(buf3))
    {
      vulnerable = TRUE;
    }
  }
  else if ('AIX' >< uname)
  {
    buf = info_send_cmd(cmd:"cat " + splunk_home + "/etc/splunk-launch.conf | grep -F 'SPLUNK_OS_USER='");
    if (!isnull(buf))
    {
      vulnerable = TRUE;
    }
  }
}
if (vulnerable)
{
  report =
    'The current configuration of the host running Splunk was found to be' +
    '\nvulnerable to a local privilege escalation vulnerability.';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else
{
  audit(AUDIT_OS_CONF_NOT_VULN, "Splunk");
}



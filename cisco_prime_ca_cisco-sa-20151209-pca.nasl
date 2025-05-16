#TRUSTED 6fc8f0d24ad9475fedc296f8d296cac6f26c1c7d034fdeb5c43a60ca36479f21e3e4a67825dd8084385275238b46d9f3e9e24238d47417be72ddc84b9296247e1bda6b1cafc188892e9cd93cf9b4a1307c0fff281ace455b7a3b8473d61732e4ca8ab1fdcf34571977d805696298377e8cf92508da6eef8e2ebe522c720e700cbe5a84fe83b89ebfcbc635df6a66dff83ee2f10e359ea5b68c50007b154cb2df42549ac3aefd7a894aaa5f2d02232ad32a2fcb3bc47411c6c0a66b06a0b0a67fc94784948287adad65636be7c4d2b945add6d3e151b89ac7d9fb65c77a8f5b50ccf201618bd34dba81b277c40bd10a33fe208f81c3920e66b5caab6547d9a809d915c7a3ce5b48af313389b24021155bd6e9942e2d7649c95a19890860615c9161ade559c15c4d6a46b1f4c72300396004850fe2cc7e310150e0f58f2936df0112184ae8552ed58be5c30cfbd84f310e4c7b7bad40e3a4552252b5684b938d9123bdd07d2e2462a036d2de1fcb18cd3d1d3f9469ecbf52ac9fd16d94016912e8bbed70dbaf7c23aeaba9ad14221a50b4128f93c32ddaada848f12764e6c4cdd056d0a1533af6bd4b2f55d367b39a5f981f78a28e16bbd89c8ec420b1a28e70f34904316226273161d27be1018265d0a6b5d80f851ba12527326f690e607216a2ba52f72befb6f2796790c1db7601ece9d38cbb4c94d9937667b0ac5d9bba1c33
#TRUST-RSA-SHA256 83068b3579d9ea968e9009a55e98e0ccd82f43d009f2d09fd8720da54fe610290bfcb4c38fd4dc5a3960bd0e5df9388380e21643b4e2f6caeb6958439563e17d8f61fa55c50ad6f5a1f969d55ed2614c8cc99ea14b6a41c150d9bc8ee0774712125adf7dfd047dcc0c4c944a5637e878843f0e567ff1ad42b30647947c9e026421b8d12760c99c2ee3ef35f9bf6396abe3ff5dc4d9f5e166833384f91ac9b582a684748892627dfc23a7a1157d77b8e3d6b2813f34d08fab1fd3e660c7f10fcf0515a9d952330cc899179e603ea16100bb935520f52770db37be87de788204a90fd7d2f36d1816ef3f74b7ff1354fd6cb905e1bf3f91f86ce10b53cea15c1dd6f56d240bc05742e5fd903b852393b9c5c257b8a765e5093bd4ca3b083222af4a4220b3ae9b9aaa552c198df9fde2cec6511b4f786e40cc6f28b6287d2ee6420bfdbcf76c44226aa3d79592b83de6b4c48b717aca2a340caf905218c34b212792038223fe93e6455095d7355a0df7eb83ac2ea4566f28f78248b27e26ecedcbb2bb20d3f5631f9212369fe802e7d3a1a2d96400f085fa6c9b07c2b796ea00870fb1a5781bedb240f594126d526a7a07a814aea8e479ba34bafe82deef6c1b98302e43716d3f3f49492c06981872e4ce7e7af5f00c968fe37209fb1e586e729dec63269dabb15203c4762994a78343bc71772db34dc0a746b16e341edbe490d732
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87506);
  script_version("1.22");

  script_cve_id("CVE-2015-6389");
  script_bugtraq_id(78738);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus62707");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151209-pca");

  script_name(english:"Cisco Prime Collaboration Assurance Default 'cmuser' Credentials (cisco-sa-20151209-pca)");
  script_summary(english:"Checks the Cisco Prime Collaboration Assurance version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management device is protected by default
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Prime Collaboration Assurance device is protected by
default credentials. This is due to an undocumented account that is
created during installation. A remote attacker can exploit this to log
in to the system shell with the default 'cmuser' user account, and
access the shell with a limited set of permissions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-pca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28fa8c84");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus62707");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Assurance version 11.0 or later.

Alternatively, a workaround is to change the default password for the
'cmuser' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6389");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_assurance");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_assurance_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationAssurance/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_lib.inc");

checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();

appname = "Prime Collaboration Assurance";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationAssurance/version");

login    = "cmuser"; # default
password = "cmuser"; # default
flag  = 0;
port  = 0;
extra = '';
report_extra = '';
report = '';

# Normal version check first
# Affected : < 11.0 per vendor
if (ver_compare(ver:version, fix:"11.0.0",  strict:FALSE) < 0)
  flag++;

# Check the workaround (are default creds gone?).
if (report_paranoia < 2 && flag)
{
  # Do not try this if the user has specified
  # that only user-supplied credentials are okay.
  if (supplied_logins_only)
    audit(AUDIT_SUPPLIED_LOGINS_ONLY);

  # Setup SSH bits
  port = sshlib::kb_ssh_transport();
  if (!get_port_state(port))
    audit(AUDIT_PORT_CLOSED, port);

  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket)
    audit(AUDIT_SOCK_FAIL, port);

  # Attempt the login with default credentials.
  login_result = ssh_login(login:login, password:password);

  # If login fails just keep port at '0' for
  # the version-check reporting.
  if (login_result != 0)
  {
    ssh_close_connection();
    port = 0;
    flag = 0;
  }
  # If login successful, attempt to run 'id'
  else
  {
    ssh_cmd_output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
    ssh_close_connection();

    if (
      ssh_cmd_output &&
      'uid' >< ssh_cmd_output
    )
    {
      # Login okay; 'id' command okay
      report_extra =
        '\n  After authenticating, Nessus executed the "id" command ' +
        '\n  which returned :' +
        '\n' +
        '\n' +
        chomp(ssh_cmd_output) +
        '\n';
    }
    else
    {
      # Login okay; BUT perhaps account is
      # administratively required to change
      # password before running commands. Or
      # any number of other mechanisms that
      # complete the login process but do not
      # allow 'id' command.
      report_extra =
      '\n  After authenticating, Nessus attempted to execute the "id" ' +
      '\n  command, but the attempt was not successful. This could ' +
      '\n  be due to the account being administratively required to ' +
      '\n  change password at login; however, the account is indeed enabled ' +
      '\n  and accessible with the default password.';
    }
  }
}

if (port || flag)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.0' +
      '\n';
    if (report_paranoia == 2)
      report_extra +=
        '\n  Note that Nessus has not attempted to login as the "cmuser" due' +
        '\n  this scan being configured as Paranoid.' +
        '\n';
    security_hole(port:port, extra:report + report_extra);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);

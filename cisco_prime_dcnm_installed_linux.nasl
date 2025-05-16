#TRUSTED 70f63c2ed1463067b7bb11b3c69ad25427ea08d2e8439e96788d963faea618c21fc599d56b4d41dce3a58b3c46eb5fc6120851565d297e697945e5903c49cbf160f5c5f3ac31bdee7f8a26bb2811161e038760ce37bfb1ae99df983688deb4973f13a6e2a6ce011df5cd824f91bfe63d31f62a7d88d96da544a84f71fb14927f607f66e098c322ec1fbcbf7e467550baf41a6be6569b2a89cf9698c98fc26606f99208391bea958f86c2e8ac937ce13638ad3d77d0e9881ed9a3cc4de6e32605464a963d79c0895ca995120a19f54a281e56b1c55ff18458296f08b6e996ec140969056874f6b1b0a05516f3296b049c8186ca697e39ce9805d7d69d19f27e37f6eed7cd2500512091c62c580ca10e7cb2ffdc486f0b0fb5e972c011840ae4aabe48a5d0e4f0fbbc778caeb48cf5c65e78daeb629865c9b68a35df5b1b383795080cb97bb97442d0cb29874896f1116affcedbb709928117463e889db0845c173ef7d5e38b8435d2819b2caa7c2499ea2d397649a4f00a55850d2fb5bef690ef9e07e18c3289527232bf2a532f81ff889abea8d92b5d9ecff13dc9440bfb2067b04d8a70058dd927600e338dc3cf55a972b166e5828835975e5179d3fb2cde52abc9e52b25dd2d5920654d010162ebda31d039ec6c0ac65686b4d2635765c4dd237e092872f36de3d5fead785ca916c028d263a2582072bde83e7bd2135abb32
#TRUST-RSA-SHA256 0715cae72d352697b5810d1d9c21a370de8b4aa916a4019793f200ac0c54f9ef5d4721bab95ec7422959623d8c5e265de31158b5a32a5ddee5b2db571315c428ea451a3f109f132701839423eef094f4ec98e6174357bcbc91c1c26a0ce12d56d720f9b91d952661573d6ba3714cebe186b197f95d61679e79f766d7491464a5cd24895ac70e9ef661375e700996c1d0d091eff3aabb6b51eace264c2f5114171c2db425e0ae42b3b8c89f1b2611241b7f9d61a76721d7b783c4710744f6f713f716a3875ac8b441c7f41aeb3a54fa5d091f317a8ab155879fb811e48a630bc4dca88f2d80da465a84b6a74e7996471a06dc5a780f600f0e5aed892b6fa36bb0c2b05bd9a67eb8c5864cc358e8614763deca5ff89b499fa8610baa71167ec9df015f8e46e95c050ae4f2a28d30b35795db86c04b1e3e344dccc58cbad5a0fcfe1cf658375c9bd5ef2171f4c177542cb4a31bbc34a0f956736f515de8a90c1d50f540e5bcfceedf541c4fad5b5b7cf33d3261daac84cd4154b8104ab6597402c6719dc084f35c42743b2c9e0f636b44e10d01ad0b9f16bd1b9e5d0c1e61166c0bcc751ad805bc02189acefeff23547bb939b833e171bf4f1ab420a09c1dcc14ee7ac55b1c7ec7f40645a3ad64bd1e5a485b7a019cd70841ea48ded2e863ef4198012ac7e2b223d03981dd4d8e6fe4b66b2ce7be43413452065cda36f98a4d0cfb
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(67244);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_xref(name:"IAVT", value:"0001-T-0556");

  script_name(english:"Cisco Prime Data Center Network Manager Installed (Linux)");

  script_set_attribute(attribute:"synopsis", value:"A network management system is installed on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"Cisco Prime Data Center Network Manager (DCNM) is installed on the
remote host. DCNM is used to manage virtualized data centers.");
  # https://www.cisco.com/c/en/us/products/cloud-systems-management/prime-data-center-network-manager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?946c0157");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto", "Host/uname");

  exit(0);
}

include('ssh_func.inc');
include('telnet_func.inc');
include('hostlevel_funcs.inc');
include('install_func.inc');

enable_ssh_wrappers();

if ('Linux' >!< get_kb_item_or_exit('Host/uname'))
  audit(AUDIT_OS_NOT, 'Linux');

proto = get_kb_item_or_exit('HostLevelChecks/proto');

installed = FALSE;

if (proto == 'local') info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

jboss_path = info_send_cmd(cmd:'grep ^JBOSS_HOME= /etc/init.d/jboss');
smis_path = info_send_cmd(cmd:'grep ^INSTALLDIR= /etc/init.d/ciscosmis');
java_path = info_send_cmd(cmd:'grep ^JAVA_HOME= /etc/init.d/FMServer');
dcnm_path = NULL;

if (jboss_path =~ '^JBOSS_HOME=')
{
  jboss_path = split(jboss_path, sep:'=', keep:FALSE);
  jboss_path = jboss_path[1];

  # example path: /usr/local/cisco/dcm/jboss-4.2.2.GA
  # everything up to and including "cisco/" is configurable during installation
  # if "dcm" is not in the path, the init script was probably not created by the
  # DCNM installer
  if (jboss_path =~ '/dcm/jboss')
  {
    trailing_dir = strstr(jboss_path, '/jboss');
    dcnm_path = jboss_path - trailing_dir;
    ver_files = make_list(
      '/Uninstall_DCNM/installvariables.properties',
      '/dcnm/Uninstall_DCNM/installvariables.properties',
      '/dcnm/Uninstall_DCNM/InstallScript.iap_xml'
    );
  }
}

if (java_path =~ '^JAVA_HOME=')
{
  java_path = split(java_path, sep:'=', keep:FALSE);
  java_path = java_path[1];

  # example path = /usr/local/cisco/dcm/java/jre1.8
  if (java_path =~ '/dcm/java')
  {
    trailing_dir = strstr(java_path, '/java');
    dcnm_path = java_path - trailing_dir;
    ver_files = make_list('/Uninstall_DCNM/installvariables.properties');
  }
}

if (smis_path =~ '^INSTALLDIR=')
{
    smis_path = split(smis_path, sep:'=', keep:FALSE);
    smis_path = smis_path[1];

    # example path = /usr/local/cisco

    if (!empty_or_null(smis_path))
    {
      dcnm_path = chomp(smis_path) + '/dcm';
      ver_files = make_list('/Uninstall_DCNM/installvariables.properties');
    }
}

# if getting the install path failed for any reason,
# check the default installation directory for 4.x
if (isnull(dcnm_path))
{
  dcnm_path = '/DCNM';
  ver_files = make_list('/Uninstall_DCNM/installvariables.properties');
}

foreach ver_file (ver_files)
{
  file = dcnm_path + ver_file;

  # replace ' with '"'"' to prevent command injection
  file = str_replace(string:file, find:"'", replace:'\'"\'"\'');
  output = info_send_cmd(cmd:"grep '\(^\(PRODUCT_VERSION_NUMBER\|DCNM_SPEC_VER\|INSTALLER_TITLE\)=\|$PRODUCT_NAME$ [0-9.]\+\)' '" + file + "'");

  # if neither of the patterns match, it's likely the file doesn't exist
  # i.e., the command executed above did not get the product version
  ver = NULL;
  match = pregmatch(string:output, pattern:'PRODUCT_VERSION_NUMBER=(.+)');
  if (!isnull(match))
  {
    ver = match[1];
    match = pregmatch(string:output, pattern:'DCNM_SPEC_VER=(.+)');
    if (isnull(match)) match = pregmatch(string:output, pattern:"Data Center Network Manager\(DCNM\) ([\d.]+\([^)]+\))");

    if (isnull(match)) display_ver = ver;
    else display_ver = match[1];
  }
  else
  {
    match = pregmatch(string:output, pattern:"\$PRODUCT_NAME\$ ([\d.]+\(\d+\))");
    if (!isnull(match) && !isnull(match[1]))
    {
      ver = match[1];
      display_ver = ver;
    }
  }

  if (isnull(ver)) continue;

  # convert versions like 5.0(2) to 5.0.2.0
  # it's possible to get a version like this if the .properties file doesn't exist,
  # but the .xml file does
  match = pregmatch(string:ver, pattern:"^([\d.]+)\((\d+)(\w)?\)$");
  if (!empty_or_null(match))
  {
    # convert lowercase letters to numbers
    # a = 1, b = 2, et cetera
    revision = match[3];
    if (isnull(revision)) revision = '0';
    else revision = ord(revision) - 0x60;

    ver = match[1] + '.' + match[2] + '.' + revision;
  }

  installed = TRUE;

  register_install(
    app_name:'Cisco Prime DCNM',
    vendor : 'Cisco',
    product : 'Prime Data Center Network Manager',
    path:dcnm_path,
    version:ver,
    display_version: display_ver,
    cpe:'cpe:/a:cisco:prime_data_center_network_manager'
  );

  break;
}
if(info_t == INFO_SSH) ssh_close_connection();

if (installed) report_installs(port:0);
else audit(AUDIT_NOT_INST, 'Cisco Prime DCNM');

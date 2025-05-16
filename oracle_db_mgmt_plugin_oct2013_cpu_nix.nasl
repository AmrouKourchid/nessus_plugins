#TRUSTED 89362e949d7bf702470fa79865988dac0a872f0194fa836fd4256d8a7fb6c2cb8c5f0b956c62580f826927446ea01ad1c9f826a32fb29652ca05e2be1562d8dec3c2dac165165ee875d3eeb0cc792b739e4453f5cc9e6c91be3cc375575ebebcfd05ac937e6841a6b3cb9b6fe0f5fb9412d901c211fab166e7a43f6da35039e88f4371fdcf706c65d46495eb0b8b30090577eb16d68eb8e944f6b6d7f323a9e6dc0f22f53ff8e327174b9ad50f9e9e6eea52beb1fe3d90d21bfafa9d877119346284200a2c634a8510c6de21f9547081e8dc1c1d2567f1d9b6880f24b93b3085d76ef9fa1b525edfcaed77e6c579a61b5e191cb67b2cffef9812ebf5732f2adbed47cebda7ef4d62af606cf6ce714ffa7c75be0b20975a497fc93a01315f6fe03893733e34f699ada269d0b8445efd9d783be3045d233958b4be859f0c5bdd5c4fba4e5f7717d1844105939d2d1679f28ef5e5862d6ae1112d752743d9103273e7a93e6c4d6915cca77a081925a55bae9d90e792dac23c541156a188af1df64c11e4b03d6d1a482f521fa929fb88084457293653b51381c1a8fac7d44ddfa3a2a1ef7bc2b2aa6c08e800260bf0174be425082b88b05e339e71d156f505c4c46b1524ddc16391764a63126f13f4a35ff236885c601ad0146b7048206622e2f087392c50ee6c3a111e65d1216767f0127d2e7b6f2f6f762286e2f080392fe34b5f
#TRUST-RSA-SHA256 23260b7dafd4f67c52498b362a9c90d98ed85c543f8c964c1698b7b653f2b90ebbade13763b9f45246e63813d7c8462437829c4ba63520e8596fec7abee0ee36e51cb3f163daa07d44fe42940de54bfb9726246231e92923d72aca8f793c15624e16550e03a041b471d83967745bc1a117de883bf725e757aeee7f3fa8f59df16273b057cd495f682fafa1421f6ea39f5c739fdda3d03a8fa513f4c8dff8b345ab9da9cf4ad41f68edd608cec11ef2bd28475f4ff92f9a534d6ada5df46e2ee06f1a4fa1924fc9430e503877e8f455f43c876e2d3392249cbd8aff7d6beb274f1758de0b32ee4e0ff8b882d3ca5d4a782d79fe203b1f7e4f9292b105ef4edc0bfeb7b838af9011cccb2fe2e7ef0a6b12837e989bb1f1e154bd16058b1fd34f7fe41887e383eb24fbde2bcc2afcb629df95e776bf144203b7ec6a1d6224286dcfb9cd6ab56dffc4ac08dc1029345a2e36e915b0b3393f13bc9a755a8f7084857e8e96619c952f93ec844a848574b697ecc0943ce4a75ed9c999174c8bf8580d22e3d43a3b565c4735694e0885f71e91e91062a78c6b4c54e82f124af9c26d71f6f35093ed0630875b1d5ffa6cd9834afeed1f675b5a1317d60f0164a06603a20802b5356183201230e179d6a93353281423bc5191629b04a42755118c0b43728494dfabfc707657244a015c4635077c6ed97fd66083092491e0e7389f2d8a254c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70546);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2013-3762",
    "CVE-2013-5766",
    "CVE-2013-5827",
    "CVE-2013-5828"
  );
  script_bugtraq_id(
    63056,
    63064,
    63068,
    63071
  );

  script_name(english:"Oracle Database Management Plug-In Unix (October 2013 CPU) (credentialed check)");
  script_summary(english:"Checks for patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"A database management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle Database Management Plug-In installed on the remote host is
missing the October 2013 Critical Patch Update (CPU). It is,
therefore, affected by multiple vulnerabilities in the Enterprise
Manager Base Platform component :

  - An unspecified flaw exists in the Schema Management
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2013-3762)

  - An unspecified flaw exists in the DB Performance
    Advisories/UIs subcomponent that allows an
    unauthenticated, remote attacker to impact integrity.
    (CVE-2013-5766)

  - Multiple unspecified flaws exist in the Storage
    Management subcomponent that allow an unauthenticated,
    remote attacker to impact integrity. (CVE-2013-5827,
    CVE-2013-5828)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2013 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5828");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_plugin_for_database_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("local_detection_nix.inc");

enable_ssh_wrappers();

if (!is_sh_command_line_os()) exit(0, "Oracle Database Management Plug-In checks are not supported on the remote OS at this time.");

# We may support other protocols here
if ( islocalhost() )
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# Find the inventory.xml file and read it in
# Parse the results to get the paths and version of the DB plugins
var info = "";

var cmd = 'cat /etc/oraInst.loc';
var cmd2 = "";
var buf = NULL;
var buf0 = NULL;
var args = [];

var path, version, item, chunk;
var paths = make_array();
var results = make_array();
buf0 = info_send_cmd(cmd:cmd);

# We want to handle that Grep and Sed within the plugin itself. This'll help breakup that large command
# and be more reliable then trusting the target box)
if (!empty_or_null(buf0))
{
  cmd2 = 'cat ';
  foreach item (split(buf0))
  {
    # Find any instances  starting with inventory_loc= (It should be a path)
    results = pregmatch(pattern:"inventory_loc=(.*?)(?:$|\n)", string:item);

    if (!empty_or_null(results) && !empty_or_null(results[1]))
    {
      append_element(var:args, value:results[1] + '/ContentsXML/inventory.xml');
      cmd2 += " '$" + max_index(args) + "$'";
    }
  }
}

# Here, we do the second cat in the original command. This will cat all the contents from the valid paths we discovered!
if (!empty_or_null(args))
{
  buf = ldnix::run_cmd_template_wrapper(template:cmd2, args:args);
}

# continue with original code here. 
# NOTE: that this is only going to look for the first instance of oms12c. We might come back to this later and adjust it
# to handle multiple instances (In the event that we have them)
if (buf)
{
  buf = chomp(buf);
  if ('HOME NAME="oms12c' >< buf)
  {
    chunk = strstr(buf, '<HOME NAME="oms12c') - '<HOME NAME="oms12c';
    chunk = strstr(chunk, '<REFHOMELIST>') - '<REFHOMELIST>';
    chunk = chunk - strstr(chunk, '</REFHOMELIST>');
    chunk = chomp(chunk);

    foreach item (split(chunk))
    {
      path = '';
      # If the item is a DB 12.1.0.3 or 12.1.0.4 plugin, save the path
      if (item =~ "/oracle\.sysman\.db\.oms\.plugin_[^/0-9]*12\.1\.0\.[2-4]($|[^0-9])")
      {
        path = ereg_replace(pattern:'^\\s+<REFHOME LOC="([^"]+)".*', string:item, replace:"\1");
        version = strstr(path, 'plugin_') - 'plugin_';
        paths[version] = path;
      }
    }
  }
}

if (max_index(keys(paths)) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, "No affected Oracle Database Management Plug-Ins were detected on the remote host.");
}

# Loop over the DB Management Plug-In paths
info = '';
var patchid;
foreach version (keys(paths))
{
  if ('12.1.0.2' >< version) patchid = '15985383';
  else if ('12.1.0.3' >< version) patchid = '17171101';
  else if ('12.1.0.4' >< version) patchid = '17366505';

  path = paths[version];
  buf = ldnix::run_cmd_template_wrapper(template:"cat '$1$'", args:[path + "/.patch_storage/interim_inventory.txt"]);

  if (empty_or_null(buf))
    info += '  ' + version + '\n';
  else
  {
    # Parse the file to see what patches have been installed
    buf = chomp(buf);
    chunk = strstr(buf, '# apply: the patch to be applied.') - '# apply: the patch to be applied.';
    chunk = chunk - strstr(chunk, '# apply: list of patches to be auto-rolled back.');
    if (!empty_or_null(chunk))
      chunk = chomp(substr(chunk, 1));

    if (patchid >!< chunk)
      info += '  ' + version + '\n';
  }
}
if (info_t == INFO_SSH) ssh_close_connection();

if (info)
{
  var report =
    '\nThe following affected Oracle Database Managment Plug-Ins were detected' +
    '\non the remote host :' +
    '\n' +
    info;
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : report
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');

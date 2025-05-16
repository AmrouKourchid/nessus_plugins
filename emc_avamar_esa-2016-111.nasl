#TRUSTED 1b64f13696dbf28439eee862729ce3d870bf6502e183835cdad9a0d62c2776a3f469d7d371e152299f2cdfcda68479860380b696ab0ea2e20bc94604d45cb4e664624b67669b0e7e576e659e408f3e0293d801ca9aebd778d09c6ac0fb16e15bd81966406a58fd96d6bd5632913061c6fbff055d52b56c57eadcd38dff2440718438084ffab25132fd1c971cd6259b45d9506a44e5f3658770fa037a9d56812b2f77d772197ef455e3855a6b4b6b7edcdc5857a6df9279eeb686809fe8f33ab9f78efe056bdef1e4c8631a21d5c85a42cf2896e63e3fe1c067bf664363fb8ccd3e38dff9d4ffa2f2767a6b9fc60cb2072611df3f39b3c46e76411b36f3fa81fed1c6294d93348b9143c805e22bbb2437f3744edd99218e055fc8bd11e766e711274719a8477cd69b476e42367b9bace5c1ebb3a1dc02a8ea51243b5865ec1f84ab27ca11de45065d69c133fa4e4818fd149972638a6896e9a6db86872d3e11ed5610e40c6d3fcbb90e54d00bda14e122e84ecf2f502b19f396bfef48f60341d14390d773f4ba905d7a521995377f77130ff7d0f4653112c6dec3a59e50ca1eec141c5df1cb4f912f2737dc8b60ac4f7a49e43f6d7c4e4b9979074cd11063d4047a000271493e510039c96670ed3db9ab06146b01a7fcd554701b58e5a073f3bca434aa1edf6bdfaf8b414ec9b2cf044232f0137829b334063790b673f7486ca4
#TRUST-RSA-SHA256 85873e4a852fff21f336b18a3087d4566010b0108b8ea3c817662a0df90e115b083cc6487fddf050106f5bcfa81f0872ae5abb09f99d8d5b9be0813b0918b9ec5b4feeb275059b00c42a71cc1a8e4b96d526cf4adf28439a974b2e0b7952c1aaa6f6076924e00790d01dfbb0464803ceed9cc284dd7d87e38843234962b19ef83df57e644a4c604c8a726dcc3b9019f5789eb6dba8940078ecf1a2ef0b679344ff9a45349fb41a82d64a668c9830bbdf30d9219f93aad4c7b3ee485a2faf86ba7ebbde07540a629bbf993ed24198e48a3f5823b8014d7510c5d6692e0b218315d1cf08fbce78555223df8481268d27c44b3caa07af1d6b6b06a1b2ef63ec04fb888fb9d895c9e8833f3b8033c8d0a9dbc5ff7d0b4736bfbfb50a30fe931d29f3d339488d2c799905b3de0743c71194c469c9e54bd1189067c926c8eb08d41bba4c7805a5b381e882313233e705c31dbe667809fef76f0ff7a9003f9fec5c2ba9089d93ced78bf332362c417175d26acd0c488ee67038cfa569de563f7b71f012a5e4c8209379203abdb5fbe27482a49d0b690faa07eabea7b9dd026d458135e1d095d78608df5ba99f3c86b94f87804ab8bcc1466bd7b120921434bce9e1510f5b563cc31041eae212d9adb99cbe39eb036fefe029402364645e93e5544b079d8cf602ced10f1809477ab200078ceb87dd3d697292159d5f987bc632a03def9f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95921);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2016-0909");
  script_bugtraq_id(93788);

  script_name(english:"EMC Avamar ADS / AVE < 7.3.0 Hotfix 263301 PostgreSQL Command Local Privilege Escalation (ESA-2016-111)");
  script_summary(english:"Checks the version and configuration of EMC Avamar.");

  script_set_attribute(attribute:"synopsis", value:
"A backup solution running on the remote host is affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the EMC Avamar Data
Store (ADS) or Avamar Virtual Edition (AVE) software running on the
remote host is a version prior to 7.3.0 Hotfix 263301 (7.3.0.233),
or the configuration is not patched. It is, therefore, affected by a
local privilege escalation vulnerability that allows a local attacker
to execute arbitrary PostgreSQL commands and thereby gain elevated
privileged.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2016/Oct/att-45/ESA-2016-111.txt");
  script_set_attribute(attribute:"see_also", value:"https://support.emc.com/kb/486276");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Avamar ADS / AVE version 7.3.0 Hotfix 263301
(7.3.0.233) and apply the configuration changes documented in
KB486276.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0909");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_data_store");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_server_virtual_edition");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_avamar_server_detect.nbin", "emc_avamar_server_installed_nix.nbin");
  script_require_keys("installed_sw/EMC Avamar");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("http.inc");
include("misc_func.inc");


enable_ssh_wrappers();

app = "EMC Avamar";
get_install_count(app_name:app, exit_if_zero:TRUE);

install = make_array();
port = 0;

if (get_kb_item("installed_sw/EMC Avamar/local"))
{
  install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
}
else
{
  port = get_http_port(default:443);
  install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
}

version    = install['version'];
version_ui = install['display_version'];
hotfixes   = install['Hotfixes'];

fix_ver = '7.3.0.233';
fix_hf  = '263301';

vuln         = FALSE; 
config_check = FALSE;

report_fix    = NULL;
insecure_file = NULL;

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) < 0)
  vuln = TRUE;

# Remote checks cannot check the configuration or hotfix reliably
if (!vuln && port != 0)
  exit(0, "The "+app+" "+version_ui+" install listening on port "+port+" may be affected but Nessus was unable to test for the issue. Please provide valid credentials to test for the issue.");

# Check for hotfixes
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0)
{
  if (empty_or_null(hotfixes))
    vuln = TRUE;
  else
  {
    hotfixes = split(hotfixes, sep:";", keep:FALSE);
    foreach hotfix (hotfixes)
    {
      if (fix_hf == hotfix)
      {
        config_check = TRUE;
        version_ui += " HF" + fix_hf;
      }
    }
    if (!config_check) vuln = TRUE;
  } 
}
# For versions later than 7.3.0.233 HF263301 we still need to check the configs
else if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) > 0)
  config_check = TRUE;

# Only check configuration if 7.3.0.233 HF263301 or higher is detected
# Look for configurations from KB486276 (https://support.emc.com/kb/486276)
if (config_check)
{
  if (!get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  # Select transport
  if (islocalhost())
  {
    if (!defined_func("pread"))
      exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
      audit(AUDIT_FN_FAIL, 'ssh_open_connection');
    info_t = INFO_SSH;
  }

  config_check = TRUE;
  path = "/usr/local/avamar/var/mc/server_data/";

  configs = make_array(
    "postgres/data/pg_hba.conf",
      [make_list("local all all peer map=mcdb",
                "hostssl all all samehost cert clientcert=1",
                "host mcdb viewuser 0.0.0.0/0 md5",
                "host mcdb viewuser ::0/0 md5"), "# PostgreSQL"],
    "postgres/data/pg_ident.conf",
      [make_list("mcdb admin admin",
                "mcdb admin viewuser",
                "mcdb root admin",
                "mcdb root viewuser"), "# PostgreSQL"],
    "postgres/data/postgresql.conf",
      [make_list("ssl = on"), "# PostgreSQL"],
    "prefs/mcserver.xml",
      [make_list('<entry key="database_sslmode" value="true" />'), "com.avamar.asn"]
  );

  foreach subpath (keys(configs))
  {
    content = info_send_cmd(cmd:"cat " + path + subpath);
    foreach config (configs[subpath][0])
    {
      conf_pattern = configs[subpath][1];

      pattern = str_replace(string:config, find:" ", replace:'\\s+');
      pattern = '^\\s*' + pattern + '\\s*';
      if (conf_pattern >< content && !preg(string:content, pattern:pattern, icase:TRUE, multiline:TRUE))
      {
        insecure_file = path + subpath;
        report_fix = "Apply the configurations as documented in KB486276." +
          '\n  Insecure file     : ' + insecure_file ;         
        vuln = TRUE;
        break;
      }
    }
    if (vuln) break;
  }
  if (info_t == INFO_SSH) ssh_close_connection();
}
else
{
  report_fix =
    fix_ver + " HF" + fix_hf + " and apply the configurations as documented in KB486276.";
}

if (!vuln)
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

report =
  '\n  Installed version : ' + version_ui +
  '\n  Fixed version     : ' + report_fix +
  '\n';

security_report_v4(
  extra    : report,
  port     : port,
  severity : SECURITY_HOLE
);

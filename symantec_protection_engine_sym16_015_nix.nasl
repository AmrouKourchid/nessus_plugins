#TRUSTED 8f56f01ab94e69b916eeb0e3247dbaa03dbc694686fb1e9a48472e32a69e212f61727e2a6e064135d546acb194a1e8e952cdccc7e00a29601f77d6208859f96114a50c4791065aea8327ec702ec495014c71c7de5504591729367e9d36157e09848a2a859f6da69e263f8bfb6057a8d661a063a2603fae6001f805c7cf02c45f5a8fe116937956989993046ab43525bf970c502b6b1783e1c6f9bcb3c96a2a89d5a4a7c73296e7250a60c00b28d1bc24e26e04c66b86b5eab661cd5539bf0002ec9315c4a738a9307851432888ad4aca9c9adc87e119e9af2dce632f1f03d458606fec233b4f7c7c496ca5237d6f21d4190d8c6caeb82cfa838eee888b6b111da60339f928a077d1e7d1f5e6638400163406959c2877d3956a39d814efda75f7bd65e0504a65629b640f23e7084925c4338310158ed5f07c5e4220f4a6d9035269e70e50ebc8ded54cc80e1803c9aab1b7a0c63dd40e09e4559c9c90ea99a03e6653e3c48bb89d9647e9eee02c56d99e3aef8dd9c2d194c245d382b986ee7a75097a263fabc930316f2d9c9a6c00658052214a5deb20926e375ddbea9dff4bf3cb6b4642cd5c5c2a3f242cc1319093c224b9ed0222f9460b8f2a4e77003a4afad3710ed3d3f3d4b9be34693b7ec4624a98c4023b0c470da452933f08c4df7e9c68fa3dd85784f36fd2589a44faabfd39283af0d63652484509bc440902c2d9ed
#TRUST-RSA-SHA256 ab24e5ddd3527b90651585d90eb8c8f99146e40b215d7c23941bdf9bbdbbb5d79d661c2054866a6dcb9d98c4020d77686d5dfabe52c3c66f44510c0f5122f1712c2ac511ba178bf956342e8afb7a1d01eb23e185faf720eecb1599957155158c8d7e1c64386a31da1d2d19034c873fadde5e709a97e1a2036af6171dbe99dd0dbd4347fdfe0d52b21c8b0212eea192a7125b7efb4662cd7e7db7f523303abe81c002a87092d40986e86bd88d9afedc5b434382089b6c02a07b480f2df5f05e59b9149f90edb5c09213436833d092eacd5ef91f03686d356c34a801ae6a2d5a2bf9be40903d7b22e7259ce4251ae168cf0ab34e33d0125c5c2bb21c2073220f581609378962b688bfdadb4d8e1488c6b26f82aa4b75a15d74d7cd298e2434b51d6e04c7d8383fdef066c349660effa13348b1f8bb83e9ce1b46b3e642289abe5224257126402cb8c3eced60aa590f662e1e9c446c03f04dcbd44b0a64ee1be5113b95d78cb972ce4ea511f23fbce3e034007971ac12650a1e73ac36e6ef84bfcf52b2fb600a83c83e72826e1a176b3b544b93b531b0b56605eb808d3987da4bf44fa27bc75bbb1cda5cb3cd2475f9a9607c5cfab74065369242fccb2026c64152e191f568b059aae6d484acb71b593d803fefa56ff55a566061f33818d2417f4bcd484d90574e2501e8fc1e24e111e2481858fbed30f131af459158fe65ed996e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93655);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_bugtraq_id(92866, 92868);
  script_xref(name:"IAVA", value:"2016-A-0256");

  script_name(english:"Symantec Protection Engine 7.0.x < 7.0.5 HF02 / 7.5.x < 7.5.5 HF01 / 7.8.x < 7.8.0 HF03 Multiple DoS (SYM16-015) (Linux)");
  script_summary(english:"Checks the version of Symantec Protection Engine.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Protection Engine (SPE) installed on the
remote Linux host is 7.0.x prior to 7.0.5 hotfix 02, 7.5.x prior to
7.5.5 hotifx 01, or 7.8.x prior to 7.8.0 hotifx 03. It is, therefore,
affected by multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the
    decomposer engine due to an out-of-bounds read error
    that occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5309)

  - A denial of service vulnerability exists in the
    decomposer engine due to memory corruption issue that
    occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5310)");
  # https://support.symantec.com/en_US/article.SYMSA1379.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0df20c4e");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.INFO3791.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Protection Engine (SPE) version 7.0.5 HF02 / 7.5.5
HF01 / 7.8.0 HF03 or later per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5310");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:protection_engine");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_protection_engine.nbin");
  script_require_keys("installed_sw/Symantec Protection Engine");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_lib.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


enable_ssh_wrappers();

app = 'Symantec Protection Engine';
port = NULL;
function check_hf(path)
{
  local_var cmd, ret, buf, match, ver;
  local_var line, matches, vuln;

  vuln = FALSE;
  cmd = "cat -v " + path + "/bin/libdec2.so";

  if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  port = sshlib::kb_ssh_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

  ret = ssh_open_connection();
  if (!ret) exit(1, 'ssh_open_connection() failed.');


  buf = ssh_cmd(cmd:cmd);
  ssh_close_connection();
  if(!empty_or_null(buf)){
    match = eregmatch(pattern:"Decomposer\^@(\d\.\d\.\d\.\d)",string:buf);
    ver = match[1];
    if(ver_compare(ver:ver, fix:"5.4.7.5", strict:FALSE) < 0) vuln = TRUE;
  }
  else audit(AUDIT_UNKNOWN_APP_VER, "Symantec Protection Engine: Decomposer Engine");
  return vuln;
}

install = get_single_install(app_name:app);
version = install["version"];
path = install["path"];
path = chomp(path);

fix = NULL;

if (version =~ "^7\.0\.[0-9.]+$")
{
  if (
    version =~ "^7\.0\.5\." &&
    check_hf(path:path)
  ) fix = "7.0.5.x with HF02 applied";

  if (version =~ "^7\.0\.[0-4]\.")
    fix = "7.0.5.x with HF02 applied";
}
else if (version =~ "^7\.5\.[0-9.]+$")
{
  if (
    version =~ "^7\.5\.5\." &&
    check_hf(path:path)
  ) fix = "7.5.5.x with HF01 applied";

  if (version =~ "^7\.5\.[0-4]\.")
    fix = "7.5.5.x with HF01 applied";
}
else if (version =~ "^7\.8\.[0-9.]+$")
{
  if (
    version =~ "^7\.8\.0\." &&
    check_hf(path:path)
  ) fix = "7.8.0.x with HF03 applied";
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (!empty_or_null(fix))
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

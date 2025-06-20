#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109800);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/08");

  script_cve_id("CVE-2017-17969", "CVE-2018-5996");

  script_name(english:"7-Zip < 18.00 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A compression utility installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of 7-Zip installed on the remote Windows host is prior to
18.0. It is, therefore, affected by multiple vulnerabilities.");
  # https://landave.io/2018/01/7-zip-multiple-memory-corruptions-via-rar-and-zip/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3028ba9");
  # https://blog.0patch.com/2018/02/two-interesting-micropatches-for-7-zip.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20df031b");
  # https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-7-zip-could-allow-for-arbitrary-code-execution_2018-009/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42df5e81");
  script_set_attribute(attribute:"see_also", value:"https://www.7-zip.org/history.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7-Zip version 18.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5996");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("7zip_installed.nbin");
  script_require_keys("installed_sw/7-Zip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = '7-Zip';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

fix = "18.00";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40804);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2009-1492");
  script_bugtraq_id(34736);
  script_xref(name:"CERT", value:"970180");
  script_xref(name:"Secunia", value:"34924");

  script_name(english:"Adobe Acrobat < 9.1.1 / 8.1.5 / 7.1.2 getAnnots() JavaScript Method PDF Handling Memory Corruption (APSB09-06)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 9.1.1 / 8.1.5 / 7.1.2.  Such versions reportedly fail to validate
input from a specially crafted PDF file before passing it to the
JavaScript method 'getAnnots()' leading to memory corruption and
possibly arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/support/security/advisories/apsa09-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-06.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 9.1.1 / 8.1.5 / 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1492");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:'vuln_publication_date', value:'2009/05/01');
  script_set_attribute(attribute:'patch_publication_date', value:'2009/05/12');
  script_set_attribute(attribute:'plugin_publication_date', value:'2009/08/28');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2024 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("installed_sw/Adobe Acrobat");

  exit(0);
}

include('install_func.inc');

var install = get_single_install(app_name:'Adobe Acrobat', exit_if_unknown_ver:TRUE);

var version = install.version;

if (
  version =~ "^[0-6]\." ||
  version =~ "^7\.(0\.|1\.[01]($|[^0-9]))" ||
  version =~ "^8\.(0\.|1\.[0-4]($|[^0-9]))" ||
  version =~ "^9\.(0\.|1\.0($|[^0-9]))"
)
{
  var version_ui = install.display_version;
  if (report_verbosity > 0 && version_ui)
  {
    var path = install.path;
    if (isnull(path)) path = "n/a";

    var report = string(
      "\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version_ui, "\n",
      "  Fix               : 9.1.1 / 8.1.5 / 7.1.2\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "Acrobat "+version+" is not affected.");

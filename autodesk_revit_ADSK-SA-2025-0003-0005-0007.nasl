#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234621);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2025-1273",
    "CVE-2025-1274",
    "CVE-2025-1277",
    "CVE-2025-1656",
    "CVE-2025-2497"
  );
  script_xref(name:"IAVA", value:"2025-A-0282");

  script_name(english:"Autodesk Revit 2025.x < 2025.4.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Revit installed on the remote host is prior to 25.4.1.0 (2025.4.1). It is, therefore, affected
by multiple vulnerabilities as referenced in the ADSK-SA-2025-0003, ADSK-SA-2025-0005 and ADSK-SA-2025-0007 advisories.

  - A maliciously crafted DWG file, when parsed through Autodesk Revit, can cause a Stack-Based Buffer
    Overflow vulnerability. A malicious actor can leverage this vulnerability to execute arbitrary code in the
    context of the current process. (CVE-2025-2497)

  - A maliciously crafted PDF file, when parsed through Autodesk applications, can force a Memory Corruption
    vulnerability. A malicious actor can leverage this vulnerability to execute arbitrary code in the context
    of the current process. (CVE-2025-1277)

  - A maliciously crafted PDF file, when linked or imported into Autodesk applications, can force a Heap-Based
    Overflow vulnerability. A malicious actor can leverage this vulnerability to cause a crash, read sensitive
    data, or execute arbitrary code in the context of the current process. (CVE-2025-1273, CVE-2025-1656)

  - A maliciously crafted RCS file, when parsed through Autodesk Revit, can force an Out-of-Bounds Write
    vulnerability. A malicious actor may leverage this vulnerability to cause a crash, cause data corruption,
    or execute arbitrary code in the context of the current process. (CVE-2025-1274)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2025-0003");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2025-0005");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2025-0007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk Revit version 25.4.1.0 (2025.4.1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2497");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:revit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_revit_win_installed.nbin");
  script_require_keys("installed_sw/Autodesk Revit");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'Autodesk Revit', 'type': 'app'},
      'requires': [{'scope': 'target', 'match': {'os': 'windows'}}],
      'check_algorithm': 'default',
      'constraints': [
        { 'min_version' : '25.0.0.0', 'fixed_version' : '25.4.1.0', 'fixed_display' : '25.4.1.0 (2025.4.1)' }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);

#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208742);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id(
    "CVE-2024-7670",
    "CVE-2024-7671",
    "CVE-2024-7672",
    "CVE-2024-7673",
    "CVE-2024-7674",
    "CVE-2024-7675"
  );
  script_xref(name:"IAVA", value:"2024-A-0598-S");

  script_name(english:"Autodesk Navisworks Manage 25.0.x < 25.0.999.0 (2025.3) Multiple Vulnerabilities (adsk-sa-2024-0015)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Navisworks Manage installed on the remote host is prior to 25.0.999.0 (2025.3). It is,
therefore, affected by multiple vulnerabilities as referenced in the adsk-sa-2024-0015 advisory.

  - A maliciously crafted DWFX file, when parsed in w3dtk.dll through Autodesk Navisworks, can force an Out-
    of-Bounds Read. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data,
    or execute arbitrary code in the context of the current process. (CVE-2024-7670)

  - A maliciously crafted DWFX file, when parsed in dwfcore.dll through Autodesk Navisworks, can force an Out-
    of-Bounds Write. A malicious actor can leverage this vulnerability to cause a crash, write sensitive data,
    or execute arbitrary code in the context of the current process. (CVE-2024-7671)

  - A maliciously crafted DWF file, when parsed in dwfcore.dll through Autodesk Navisworks, can force an Out-
    of-Bounds Write. A malicious actor can leverage this vulnerability to cause a crash, write sensitive data,
    or execute arbitrary code in the context of the current process. (CVE-2024-7672)

  - A maliciously crafted DWFX file, when parsed in w3dtk.dll through Autodesk Navisworks, can force a Heap-
    based Buffer Overflow. A malicious actor can leverage this vulnerability to cause a crash or execute
    arbitrary code in the context of the current process. (CVE-2024-7673)

  - A maliciously crafted DWF file, when parsed in dwfcore.dll through Autodesk Navisworks, can force a Heap-
    based Buffer Overflow. A malicious actor can leverage this vulnerability to cause a crash or execute
    arbitrary code in the context of the current process. (CVE-2024-7674)

  - A maliciously crafted DWF file, when parsed in w3dtk.dll through Autodesk Navisworks, can force a Use-
    After-Free. A malicious actor can leverage this vulnerability to cause a crash or execute arbitrary code
    in the context of the current process. (CVE-2024-7675)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2024-0015");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk Navisworks Manage version 25.0.999.0 (2025.3) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7675");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:autodesk:navisworks_manage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_navisworks_manage_win_installed.nbin");
  script_require_keys("installed_sw/Autodesk Navisworks Manage", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf_extras_autodesk.inc');

var app_info = vcf::autodesk::navisworks::get_app_info(type:'Manage');

var constraints = [
  { 'min_version' : '2025', 'fixed_version' : '2025.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

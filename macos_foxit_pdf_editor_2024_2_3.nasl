#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207698);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_name(english:"Foxit PDF Editor for Mac < 2024.2.3 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote macOS host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor for Mac application (previously named Foxit PhantomPDF for Mac) installed
on the remote macOS host is prior to 2024.2.3. It is, therefore affected by vulnerability. Foxit has released Foxit PDF 
Editor for Mac 2024.2.3, which addresses potential security and stability issues.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor for Mac version 2024.2.3 or later");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_phantompdf_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit PhantomPDF");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Foxit PhantomPDF');

var constraints = [
  { 'min_version' : '2024.1.0', 'max_version' : '2024.1.0.63682', 'fixed_version' : '2024.2.3' },
  { 'min_version' : '2024.2.0', 'max_version' : '2024.2.0.64371', 'fixed_version' : '2024.2.3' },
  { 'min_version' : '2024.2.1', 'max_version' : '2024.2.1.64379', 'fixed_version' : '2024.2.3' },
  { 'min_version' : '2024.2.2', 'max_version' : '2024.2.2.64388', 'fixed_version' : '2024.2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190096);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id("CVE-2021-27034", "CVE-2021-27035", "CVE-2021-27036");

  script_name(english:"Autodesk Design Review Multiple Vulnerabilities (adsk-sa-2021-0003)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Autodesk Design Review installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Design Review installed on the remote Windows host is a version prior to 2018 hotfix 4. 
It is, therefore, affected by multiple vulnerabilities.

  - A heap-based buffer overflow could occur while parsing PICT, PCX, RCL or TIFF files in Autodesk Design 
    Review 2018, 2017, 2013, 2012, 2011. This vulnerability can be exploited to execute arbitrary code. 
    (CVE-2021-27034)

  - A maliciously crafted TIFF, TIF, PICT, TGA, or DWF files in Autodesk Design Review 2018, 2017, 2013, 
    2012, 2011 can be forced to read beyond allocated boundaries when parsing the TIFF, PICT, TGA or DWF 
    files. This vulnerability in conjunction with other vulnerabilities could lead to code execution in the 
    context of the current process. (CVE-2021-27035)

  - A maliciously crafted PCX, PICT, RCL, TIF, BMP, PSD or TIFF file can be used to write beyond the 
    allocated buffer while parsing PCX, PDF, PICT, RCL, BMP, PSD or TIFF files. This vulnerability can be 
    exploited to execute arbitrary code. (CVE-2021-27036)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2021-0003");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk Design Review version 14.0.4.198 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27036");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_dr_installed.nbin");
  script_require_keys("installed_sw/Autodesk Design Review");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Autodesk Design Review', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '14.0.4.198' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210946);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2024-46951",
    "CVE-2024-46952",
    "CVE-2024-46953",
    "CVE-2024-46954",
    "CVE-2024-46955",
    "CVE-2024-46956"
  );
  script_xref(name:"IAVB", value:"2024-B-0170-S");

  script_name(english:"Artifex Ghostscript < 10.04.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities exist in Artifex Ghostscript versions prior to 10.04.0. See vendor advisory for more 
details. 

  - An issue was discovered in pdf/pdf_xref.c in Artifex Ghostscript before 10.04.0. There is a buffer 
    overflow during handling of a PDF XRef stream (related to W array values). (CVE-2024-46952)

  - An issue was discovered in decode_utf8 in base/gp_utf8.c in Artifex Ghostscript before 10.04.0. Overlong 
    UTF-8 encoding leads to possible ../ directory traversal. (CVE-2024-46954)

  - An issue was discovered in psi/zfile.c in Artifex Ghostscript before 10.04.0. Out-of-bounds data access 
    in filenameforall can lead to arbitrary code execution. (CVE-2024-46956) 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ghostscript.readthedocs.io/en/gs10.04.0/News.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Artifex Ghostscript 10.04.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include('vcf.inc');

var app = 'Ghostscript';

var constraints = [{'fixed_version' : '10.4.0'}];

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208256);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/27");

  script_cve_id("CVE-2024-9112", "CVE-2024-9113", "CVE-2024-9114");

  script_name(english:"FastStone Image Viewer <= 7.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An image viewing application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of FastStone Image Viewer installed on the remote Windows host is prior to or equal to 7.8. It is,
therefore, affected by multiple vulnerabilities:

  - A specific flaw exists within the parsing of PSD files. The issue results from the lack of proper validation of 
    user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this 
    vulnerability to execute code in the context of the current process. (CVE-2024-9112)

  - A specific flaw exists within the parsing of TGA files. The issue results from the lack of proper validation of 
    user-supplied data, which can result in a write past the end of an allocated buffer. An attacker can leverage this 
    vulnerability to execute code in the context of the current process. (CVE-2024-9113)

  - A specific flaw exists within the parsing of GIF files. The issue results from the lack of proper validation of 
    user-supplied data, which can result in a write past the end of an allocated buffer. An attacker can leverage this 
    vulnerability to execute code in the context of the current process. (CVE-2024-9114)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-1273/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-1274/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-1275/");
  script_set_attribute(attribute:"solution", value:
"See linked advisories for more details.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:faststone:image_viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("faststone_image_viewer_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/FastStone Image Viewer");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'FastStone Image Viewer', win_local:TRUE);

var constraints = [
  { 'max_version' : '7.8', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

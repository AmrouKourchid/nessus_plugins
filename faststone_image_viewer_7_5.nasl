#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208258);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2021-26233",
    "CVE-2021-26236",
    "CVE-2021-26237",
    "CVE-2022-36947"
  );

  script_name(english:"FastStone Image Viewer <= 7.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An image viewing application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of FastStone Image Viewer installed on the remote Windows host is prior to or equal to 7.5. It is,
therefore, affected by multiple vulnerabilities:

  - Unsafe Parsing of a PNG tRNS chunk in FastStone Image Viewer through 7.5 results in a stack buffer overflow.
    (CVE-2022-36947)

  - A user mode write access violation at 0x00402d7d, triggered when a user opens or views a malformed CUR file that 
    is mishandled by FSViewer.exe. Attackers could exploit this issue for a Denial of Service (DoS) or possibly to 
    achieve code execution. (CVE-2021-26237) 

  - A Stack-based Buffer Overflow at 0x005BDF49, affecting the CUR file parsing functionality (BITMAPINFOHEADER 
    Structure, ‘BitCount‘ file format field), which will end up corrupting the Structure Exception Handler (SEH). 
    Attackers could exploit this issue to achieve code execution when a user opens or views a malformed/specially 
    crafted CUR file. (CVE-2021-26236) 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2022-36947");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2021-26237");
  script_set_attribute(attribute:"see_also", value:"https://voidsec.com/advisories/cve-2021-26236/");
  script_set_attribute(attribute:"see_also", value:"https://voidsec.com/advisories/cve-2021-26233/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FastStone Image Viewer version 7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26237");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-36947");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
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
  { 'fixed_version' : '7.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

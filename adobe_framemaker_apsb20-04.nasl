#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133694);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2020-3720",
    "CVE-2020-3721",
    "CVE-2020-3722",
    "CVE-2020-3723",
    "CVE-2020-3724",
    "CVE-2020-3725",
    "CVE-2020-3726",
    "CVE-2020-3727",
    "CVE-2020-3728",
    "CVE-2020-3729",
    "CVE-2020-3730",
    "CVE-2020-3731",
    "CVE-2020-3732",
    "CVE-2020-3733",
    "CVE-2020-3734",
    "CVE-2020-3735",
    "CVE-2020-3736",
    "CVE-2020-3737",
    "CVE-2020-3738",
    "CVE-2020-3739",
    "CVE-2020-3740"
  );
  script_xref(name:"IAVB", value:"2020-B-0007-S");

  script_name(english:"Adobe FrameMaker 2019 < 15.0.5 (2019.0.5) Arbitrary Code Execution (APSB20-04)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host is prior to Adobe FrameMaker 2019 15.0.5. It is,
therefore, affected by multiple vulnerabilities as referenced in the apsb20-04 advisory.

  - Adobe Framemaker versions 2019.0.4 and below have a memory corruption vulnerability. Successful
    exploitation could lead to arbitrary code execution. (CVE-2020-3739, CVE-2020-3740)

  - Adobe Framemaker versions 2019.0.4 and below have a buffer error vulnerability. Successful exploitation
    could lead to arbitrary code execution. (CVE-2020-3734)

  - Adobe Framemaker versions 2019.0.4 and below have a heap overflow vulnerability. Successful exploitation
    could lead to arbitrary code execution. (CVE-2020-3731, CVE-2020-3735)

  - Adobe Framemaker versions 2019.0.4 and below have an out-of-bounds write vulnerability. Successful
    exploitation could lead to arbitrary code execution. (CVE-2020-3720, CVE-2020-3721, CVE-2020-3722,
    CVE-2020-3723, CVE-2020-3724, CVE-2020-3725, CVE-2020-3726, CVE-2020-3727, CVE-2020-3728, CVE-2020-3729,
    CVE-2020-3730, CVE-2020-3732, CVE-2020-3733, CVE-2020-3736, CVE-2020-3737, CVE-2020-3738)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb20-04.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker 2019.0.5 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe FrameMaker', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '15.0.5', 'fixed_display' : '15.0.5 (aka 2019.0.5)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

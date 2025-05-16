#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211725);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-11477");
  script_xref(name:"IAVA", value:"2024-A-0765-S");

  script_name(english:"7-Zip < 24.07 RCE (ZDI-24-1532)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of 7-Zip installed on the remote host is prior to 24.07. It is, therefore, affected by a remote code
execution vulnerability as referenced in the ZDI-24-1532 advisory.

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of 7-Zip.
    Interaction with this library is required to exploit this vulnerability but attack vectors may vary 
    depending on the implementation. The specific flaw exists within the implementation of Zstandard 
    decompression. The issue results from the lack of proper validation of user-supplied data, which can
    result in an integer underflow before writing to memory. An attacker can leverage this vulnerability to 
    execute code in the context of the current process. (CVE-2024-11477)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-1532/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7-Zip version 24.07 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("7zip_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/7-Zip");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'7-Zip', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '24.07' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

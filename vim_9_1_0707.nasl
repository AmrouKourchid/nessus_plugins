#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206645);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2024-45306");
  script_xref(name:"IAVA", value:"2024-A-0536-S");

  script_name(english:"Vim < 9.1.0707 Buffer Overflow Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the version of Vim installed on the remote Windows host is prior to 9.1.0707. It is, 
therefore affected by a buffer overflow vulnerability. Patch v9.1.0038 optimized how the cursor position is 
calculated and in doing so introduced the possibility for heap-buffer-overflow when trying to access the line 
pointer under specific conditions, leading to observed program crashes and other potential vulnerabilities.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/vim/vim/security/advisories/GHSA-wxf9-c5gx-qrwr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?548fa0b3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.1.0707 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'min_version' : '9.1.0038', 'fixed_version' : '9.1.0707' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

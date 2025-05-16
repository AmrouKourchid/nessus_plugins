#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185733);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2023-34049");
  script_xref(name:"IAVA", value:"2023-A-0609-S");

  script_name(english:"SaltStack 3000 <  3005.4 / 3006 < 3006.4 Security Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The version of SaltStack running on the remote server is affected by security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of SaltStack hosted on the remote server is affected by
a security bypass vulnerability. The Salt-SSH pre-flight option copies the script to the target at a predictable path, 
which allows an attacker to force Salt-SSH to run their script. If an attacker has access to the target VM and knows 
the path to the pre-flight script before it runs they can ensure Salt-SSH runs their script with the privileges of 
the user running Salt-SSH.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version");
  # https://saltproject.io/security-announcements/2023-10-27-advisory/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40d8b9d6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SaltStack version referenced in the vendor security advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:saltstack:salt");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("saltstack_salt_linux_installed.nbin");
  script_require_keys("installed_sw/SaltStack Salt Master");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'SaltStack Salt Master');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '3000.0', 'fixed_version' : '3005.4' },
  { 'min_version' : '3006.0', 'fixed_version' : '3006.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

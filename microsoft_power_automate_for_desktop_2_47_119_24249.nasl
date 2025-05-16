#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206973);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id("CVE-2024-43479");

  script_name(english:"Microsoft Power Automate For Desktop Remote Code Execution (CVE-2024-43479)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Power Automate for desktop installed on the remote Windows host is 2.41.x < 2.41.178.24249,
2.42.x < 2.42.331.24249, 2.43.x < 2.43.249.24249, 2.44.x < 2.44.55.24249, 2.45.x < 2.45.404.24249, 2.46.x <
2.46.181.24249, or 2.47.x < 2.47.119.24249. It is, therefore, affected by a remote code execution vulnerability:

  - The attacker can execute arbitrary Desktop Flows scripts in the target user session by registering the machine to
    their own malicious Entra tenant, extracting the user's Sid, and creating a malicious AD domain with the same Sid.
    This allows them to mint valid Entra ID tokens that the attacked machine will trust to run desktop automation in
    the session of the user with the matching Sid. (CVE-2024-43479)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43479");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Power Automate for desktop version 2.41.178.24249, 2.42.331.24249, 2.43.249.24249, 2.44.55.24249,
2.45.404.24249, 2.46.181.24249, or 2.47.119.24249 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:power_automate_for_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_power_automate_for_desktop_installed.nbin");
  script_require_keys("installed_sw/Microsoft Power Automate for desktop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Microsoft Power Automate for desktop', win_local:TRUE);

var constraints = [
  { 'min_version':'2.41', 'fixed_version' : '2.41.178.24249' },
  { 'min_version':'2.42', 'fixed_version' : '2.42.331.24249' },
  { 'min_version':'2.43', 'fixed_version' : '2.43.249.24249' },
  { 'min_version':'2.44', 'fixed_version' : '2.44.55.24249' },
  { 'min_version':'2.45', 'fixed_version' : '2.45.404.24249' },
  { 'min_version':'2.46', 'fixed_version' : '2.46.181.24249' },
  { 'min_version':'2.47', 'fixed_version' : '2.47.119.24249' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

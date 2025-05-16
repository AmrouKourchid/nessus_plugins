#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192025);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2024-20671");
  script_xref(name:"IAVA", value:"2024-A-0155");

  script_name(english:"Security Updates for Windows Defender (March 2024)");

  script_set_attribute(attribute:"synopsis", value:
"An antimalware application installed on the remote host is affected by a security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Antimalware Platform version of Microsoft Windows Defender installed on the remote Windows host is prior to
4.18.24010.12. It is, therefore, affected by a security feature bypass vulnerability. An authenticated attacker 
who successfully exploited this vulnerability could prevent Microsoft Defender from starting.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-20671
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4de0382c");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Defender to platform version 4.18.24010.12 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_defender_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/svcs");
  script_require_ports(139, 445);

  exit(0);
}


include('vcf.inc');

var app = 'Windows Defender';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

# Check if disabled
if (!isnull(app_info['Disabled']))
  exit(0,'Windows Defender is disabled.');

var constraints = [{'min_version':'4.0', 'fixed_version':'4.18.24010.12'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

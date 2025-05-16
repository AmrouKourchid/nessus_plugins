#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207794);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/26");

  script_cve_id("CVE-2024-39717");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/13");

  script_name(english:"Versa Director Authenticated Remote Code Execution (CVE-2024-39717)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Versa Director installed on the remote host is affected by an authenticated remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Versa Director installed on the remote host is affected by an authenticated remote code execution vulnerability:

  - The Versa Director GUI provides an option to customize the look and feel of the user interface. This option is only
    available for a user logged with Provider-Data-Center-Admin or Provider-Data-Center-System-Admin. (Tenant level
    users do not have this privilege). The “Change Favicon” (Favorite Icon) option can be mis-used to upload a
    malicious file ending with .png extension to masquerade as image file. This is possible only after a user with
    Provider-Data-Center-Admin or Provider-Data-Center-System-Admin has successfully authenticated and logged in.

Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  # https://versa-networks.com/blog/versa-security-bulletin-update-on-cve-2024-39717-versa-director-dangerous-file-type-upload-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48bd42f3");
  # https://blog.lumen.com/taking-the-crossroads-the-versa-director-zero-day-exploitation/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a68739e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Versa Director 22.1.4 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39717");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:versa-networks:versa_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("versa_director_nix_installed.nbin");
  script_require_keys("installed_sw/Versa Director");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Versa Director');

var constraints = [
  {'max_version':'21.2.2', 'fixed_display' : '21.2.3 with June 21, 2024 Hot Fix' },
  {'equal':'21.2.3', 'require_paranoia':TRUE, 'fixed_display':'21.2.3 with June 21, 2024 Hot Fix' },
  {'min_version':'22.0.0', 'max_version':'22.1.1', 'fixed_display':'22.1.4' },
  {'equal':'22.1.2', 'require_paranoia':TRUE, 'fixed_display':'22.1.2 with June 21, 2024 Hot Fix' },
  {'equal':'22.1.3', 'require_paranoia':TRUE, 'fixed_display':'22.1.3 with June 21, 2024 Hot Fix' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
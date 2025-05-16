#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211735);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id("CVE-2024-52522");
  script_xref(name:"IAVB", value:"2024-B-0181");

  script_name(english:"RClone 1.59.x < 1.68.2 Privilege Escalation (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of rclone installed on the remote macOS / Mac OS X host is prior to 1.68.2. It is, therefore, affected by
a privilege escalation vulnerability due to insecure handling of symlinks with --links and --metadata while copying 
to local disk. This vulnerability could allow unprivileged users to indirectly modify ownership and permissions on symlink target files 
when a superuser or privileged process performs a copy. This vulnerability could enable privilege escalation 
and unauthorized access to critical system files (e.g., /etc/shadow), compromising system integrity,
confidentiality, and availability. An unprivileged user can create a symlink to /etc/sudoers, /etc/shadow or similar
and wait for a privileged user or process to copy/backup/mirror users data (using --links and --metadata) resulting 
in the unprivileged user now owning the file symlinked to.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/rclone/rclone/security/advisories/GHSA-hrxh-9w67-g4cv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34f860d4");
  script_set_attribute(attribute:"see_also", value:"https://rclone.org/changelog/#v1-68-2-2024-11-15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to rclone to version 1.68.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52522");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rclone:rclone");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rclone_macos_installed.nbin");
  script_require_keys("installed_sw/rclone", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'rclone');

var constraints = [
  { 'min_version' : '1.59.0', 'fixed_version' : '1.68.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

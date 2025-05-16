#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183241);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/16");

  script_cve_id("CVE-2022-21724", "CVE-2023-3486", "CVE-2023-39143");

  script_name(english:"PaperCut MF < 20.1.9 / 21.x < 21.2.13 / 22.x < 22.1.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"PaperCut MF installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PaperCut MF installed on the remote Windows host is affected by multiple vulnerabilities, as follows:

    - An authentication bypass exists that could allow a remote, unauthenticated attacker to upload arbitrary files to
      the PaperCut host’s file storage. This could exhaust system resources and prevent the service from operating as
      expected. (CVE-2023-3486)

    - A path traversal, enabling attackers to upload, read, or delete arbitrary files. This leads to remote code
      execution when external device integration is enabled (a very common configuration). (CVE-2023-39143)

    - A third party library issue in pgjdbc. pgjdbc is the offical PostgreSQL JDBC Driver. A security hole was found in
      the jdbc driver for postgresql database while doing security research. The system using the postgresql library
      will be attacked when attacker control the jdbc url or properties. pgjdbc instantiates plugin instances based on
      class names provided via authenticationPluginClassName, sslhostnameverifier, socketFactory, sslfactory,
      sslpasswordcallback connection properties. However, the driver did not verify if the class implements the expected 
      interface before instantiating the class. This can lead to code execution loaded via arbitrary classes. Users
      using plugins are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-21724)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.papercut.com/kb/Main/securitybulletinjuly2023/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PaperCut MF version 20.1.9, 21.2.13, 22.1.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21724");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-39143");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:papercut:papercut_mf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("papercut_mf_win_installed.nbin");
  script_require_keys("installed_sw/PaperCut MF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'PaperCut MF', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '20.1.9' },
  { 'min_version' : '21.0', 'fixed_version' : '21.2.13' },
  { 'min_version' : '22.0', 'fixed_version' : '22.1.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

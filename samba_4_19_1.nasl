#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183022);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/14");

  script_cve_id("CVE-2023-3961", "CVE-2023-42670");
  script_xref(name:"IAVA", value:"2023-A-0535");

  script_name(english:"Samba 4.16 < 4.17.12 / 4.18.x < 4.18.8 / 4.19.x < 4.19.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is potentially affected by multiple vulnerabilities, as follows:

  - Insufficient sanitisation of incoming client pipe names leading to directory traversal outside of the
    private directory meant to restrict the services that clients could connect to. Depending on the 
    service the client can connect to, the client may be able to trigger adverse events such as denial of
    service, crashing the service, or potentially compromising it. (CVE-2023-3961)

  - When Samba's RPC server is under load, or otherwise not responding, the servers NOT built for the
    AD DC can be incorrectly started, and compete to listen on the same unix domain sockets. This then
    results in some queries being answered by the AD DC, and some not. This issue can be triggered
    maliciously, to prevent service on the AD DC. (CVE-2023-42670)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-3961.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-42690.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.17.12, 4.18.8, or 4.19.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::samba::get_app_info();

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version':'4.16',  'fixed_version':'4.17.12'},
  {'min_version':'4.18',  'fixed_version':'4.18.8'},
  {'min_version':'4.19',  'fixed_version':'4.19.1'}
];

vcf::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  require_paranoia: TRUE, # Require paranoia due to backporting concerns
  severity: SECURITY_HOLE
);

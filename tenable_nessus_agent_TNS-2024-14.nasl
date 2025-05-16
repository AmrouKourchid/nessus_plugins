#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207054);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-6119", "CVE-2024-45491", "CVE-2024-45492");

  script_name(english:"Tenable Nessus Agent < 10.7.3 and earlier Multiple Vulnerabilities (TNS-2024-14)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus Agent running on the remote host is prior to 10.7.2 and
earlier. It is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-14 advisory.

  - Nessus Agent leverages third-party software to help provide underlying functionality. Several of the
    third-party components (OpenSSL, expat) were found to contain vulnerabilities, and updated versions have
    been made available by the providers.Out of caution and in line with best practice, Tenable has opted to
    upgrade these components to address the potential impact of the issues. Nessus Agent Version 10.7.3
    updates OpenSSL to version 3.0.15 and expat to version 2.6.3 to address the identified
    vulnerabilities. Tenable has released Nessus Agent 10.7.3 to address these issues. The installation files
    can be obtained from the Tenable Downloads Portal (https://www.tenable.com/downloads/nessus-agents).
    (CVE-2024-45491, CVE-2024-45492, CVE-2024-6119)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/nessus-agent/2024.htm#10.7.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40ead603");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent 10.7.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45492");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin", "nessus_agent_installed_macos.nbin", "nessus_agent_installed_linux.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

var constraints = [
  { 'max_version' : '10.7.2', 'fixed_version' : '10.7.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

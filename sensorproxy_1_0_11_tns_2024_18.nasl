#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209979);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/31");

  script_cve_id("CVE-2024-6119");

  script_name(english:"Tenable Sensor Proxy < 1.0.11 (TNS-2024-18)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Sensor Proxy installed on the remote system is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Sensor Proxy running on the remote host is prior to 1.0.11. It is,
therefore, affected by a vulnerability as referenced in the TNS-2024-18 advisory.

  - Sensor Proxy leverages third-party software to help provide underlying functionality. One of the third-
    party components (OpenSSL) was found to contain vulnerabilities, and updated versions have been made
    available by the provider.Out of caution and in line with best practice, Tenable has opted to upgrade
    these components to address the potential impact of the issues. Sensor Proxy 1.0.11 updates OpenSSL to
    version 3.0.15 to address the identified vulnerabilities. Tenable has released Sensor Proxy 1.0.11 to
    address these issues. The installation files can only be obtained via Tenable Downloads Portal
    (https://www.tenable.com/downloads/sensor-proxy). (CVE-2024-6119)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Sensor Proxy 1.0.11 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:sensorproxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sensorproxy_installed.nbin");
  script_require_ports("installed_sw/Tenable Sensor Proxy");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Tenable Sensor Proxy');

var constraints = [
  { 'max_version' : '1.0.10', 'fixed_version' : '1.0.11' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

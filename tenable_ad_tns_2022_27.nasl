#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183964);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2022-37026");

  script_name(english:"Tenable.ad < 3.29.4 / 3.19.12 / 3.11.9 Client Authentication Bypass (TNS-2022-27)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable.ad (now Tenable Identity Exposure) installed on the remote system is affected 
by a client authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable.ad running on the remote host is prior to 3.29.4 / 
3.19.12 / 3.11.9. Tenable.ad leverages third-party software to help provide underlying functionality. 
One of the third-party components (Erlang) was found to contain a Client Authentication Bypass in 
certain client-certification situations for SSL, TLS, and DTLS. Out of caution and in line with best 
practice, Tenable has opted to upgrade these components to address the potential impact of the issues. 
Tenable.ad on-premise versions 3.29.4, 3.19.12 and 3.11.9 update Erlang to version 25.1.2 to address 
the identified vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-27");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/downloads/identity-exposure");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable.ad 3.29.4 / 3.19.12 / 3.11.9 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:tenable_identity_exposure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:tenable_ad");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ad_win_installed.nbin", "tenable_ad_web_detect.nbin");
  script_require_keys("installed_sw/Tenable.ad");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable.ad';

var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'min_version' : '3.11.3', 'max_version' : '3.11.7', 'fixed_version' : '3.11.9' },
  { 'min_version' : '3.19.8', 'max_version' : '3.19.11', 'fixed_version' : '3.19.12' },
  { 'min_version' : '3.29.3', 'max_version' : '3.29.3', 'fixed_version' : '3.29.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

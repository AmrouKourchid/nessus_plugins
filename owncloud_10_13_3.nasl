#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189276);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/22");

  script_cve_id("CVE-2023-49103", "CVE-2023-49104", "CVE-2023-49105");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/21");

  script_name(english:"ownCloud Server < 10.13.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of ownCloud installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ownCloud installed on the remote host is prior to 10.13.3. It is, therefore, affected by multiple 
vulnerabilities:

  - An issue was discovered in ownCloud owncloud/graphapi The graphapi app relies on a third-party GetPhpInfo.php 
    library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment 
    (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, 
    these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, 
    and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes 
    various other potentially sensitive configuration details that could be exploited by an attacker to gather information 
    about the system. Therefore, even if ownCloud is not running in a containerized environment, this vulnerability should 
    still be a cause for concern (CVE-2023-49103)

  - An issue was discovered in ownCloud owncloud/oauth2 when Allow Subdomains is enabled. An attacker is able to pass in a 
    crafted redirect-url that bypasses validation, and consequently allows an attacker to redirect callbacks to a Top Level 
    Domain controlled by the attacker. (CVE-2023-49104)

  - An issue was discovered in ownCloud owncloud/core. An attacker can access, modify, or delete any file without authentication 
    if the username of a victim is known, and the victim has no signing-key configured. This occurs because pre-signed URLs can 
    be accepted even when no signing-key is configured for the owner of the files. (CVE-2023-49105)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://owncloud.com/news/immediate-action-required-critical-security-updates-for-owncloud/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e204fc34");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ownCloud version 10.13.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49105");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:owncloud:owncloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("owncloud_owncloud_web_detect.nbin", "owncloud_owncloud_nix_installed.nbin");
  script_require_keys("installed_sw/OwnCloud OwnCloud");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');

var app = 'OwnCloud OwnCloud';
var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { 'fixed_version' : '10.13.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
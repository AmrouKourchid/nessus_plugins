#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213276);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-48872", "CVE-2024-54083", "CVE-2024-54682");
  script_xref(name:"IAVA", value:"2024-A-0835-S");

  script_name(english:"Mattermost Server 9.5.x < 9.5.13, 9.11.x < 9.11.5, 10.0.x < 10.0.3, 10.1.x < 10.1.3, 10.2.0 (MMSA-2024-00388, MMSA-2024-00392)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server installed on the remote host is prior to 9.5.13, 9.11.5, 10.0.3, 10.1.3 or 10.2.0. It
is, therefore, affected by the vulnerabilities as referenced in the MMSA-2024-00388 and MMSA-2024-00392 advisories:

  - Mattermost fails to prevent concurrently checking and updating the failed login attempts. 
    which allows an attacker to bypass of 'Max failed attempts' restriction and send a big 
    number of login attempts before being blocked via simultaneously sending multiple 
    login requests (CVE-2024-48872)

  - Mattermost fails to properly validate the type of callProps which allows a user to cause a 
    client side (webapp and mobile) DoS to users of particular channels, by sending a specially 
    crafted post. (CVE-2024-54083)

  - Mattermost fails fails to limit the file size for slack import file uploads which allows a 
    user to cause a DoS via zip bomb by importing data in a team they are a team admin.
    (CVE-2024-54682)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 9.5.13 / 9.11.5 / 10.0.3 / 10.1.3, 10.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54083");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-48872");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Mattermost Server');

var constraints = [
  { 'min_version' : '9.5', 'fixed_version' : '9.5.13' },
  { 'min_version' : '9.11', 'fixed_version' : '9.11.5' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.3' },
  { 'min_version' : '10.1', 'fixed_version' : '10.1.3', 'fixed_display' : '10.1.3, 10.2.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201927);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/08");

  script_cve_id("CVE-2024-2973");
  script_xref(name:"IAVA", value:"2024-A-0376");

  script_name(english:"Juniper SSR Security Bypass (JSA83126)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"An Authentication Bypass Using an Alternate Path or Channel vulnerability in Juniper Networks Session Smart Router or
conductor running with a redundant peer allows a network based attacker to bypass authentication and take full
control of the device. Only routers or conductors that are running in high-availability redundant configurations are
affected by this vulnerability. No other Juniper Networks products or platforms are affected by this issue. This issue
affects: Session Smart Router:  * All versions before 5.6.15,  * from 6.0 before 6.1.9-lts,  * from 6.2 before 6.2.5-sts.
Session Smart Conductor:  * All versions before 5.6.15,  * from 6.0 before 6.1.9-lts,  * from 6.2 before 6.2.5-sts.
WAN Assurance Router:  * 6.0 versions before 6.1.9-lts,  * 6.2 versions before 6.2.5-sts.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-06-Out-Of-Cycle-Security-Bulletin-Session-Smart-Router-SSR-On-redundant-router-deployments-API-authentication-can-be-bypassed-CVE-2024-2973?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4fd3d230");
  script_set_attribute(attribute:"solution", value:
"Upgrade relevant version from the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2973");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:juniper:ssr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("juniper_session_smart_router_version.nbin");
  script_require_keys("installed_sw/Juniper Session Smart Router");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Juniper Session Smart Router');

vcf::check_all_backporting(app_info:app_info);

var constraints = [ {'fixed_version': '5.6.15'},
                    {'min_version': '6.0', 'fixed_version': '6.1.9'},
                    {'min_version': '6.2', 'fixed_version': '6.2.5'} ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
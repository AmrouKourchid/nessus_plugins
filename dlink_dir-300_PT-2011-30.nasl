#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204917);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2011-4723");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");

  script_name(english:"DLink DIR Information Disclosure (PT-2011-30)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of DLink DIR installed on the remote host is affected by information disclosure Vulnerability 
as referenced in the PT-2011-30 advisory. The D-Link DIR-300 router stores cleartext passwords, which allows 
context-dependent attackers to obtain sensitive information via unspecified vectors. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://vulners.com/ptsecurity/PT-2011-30");
  script_set_attribute(attribute:"solution", value:
"Upgrade DLink DIR based upon the guidance specified in PT-2011-30.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4723");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:d-link:DIR-300");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dlink_dir_www_detect.nbin");
  script_require_keys("installed_sw/DLink DIR");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80, embedded:TRUE);

var app_info = vcf::get_app_info(app:'DLink DIR', port:port, webapp:TRUE);

if (empty_or_null(app_info['model']) ||
    'DIR-300' >!< app_info['model'])
    audit(AUDIT_DEVICE_NOT_VULN, 'DLink DIR model');

var constraints = [
  { 'fixed_version' : '99.99', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
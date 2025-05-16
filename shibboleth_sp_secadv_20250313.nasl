#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233773);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-31335");
  script_xref(name:"IAVB", value:"2025-B-0045");

  script_name(english:"Shibboleth < 3.5.0.1 Forged Messages");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a single-sign-on service provider installed which is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Shibboleth Service Provider installed on the remote is prior to 3.5.0.1. It is, therefore, affected by
a vulnerability. The OpenSAML C++ library before 3.3.1 allows forging of signed SAML messages via parameter manipulation
(when using SAML bindings that rely on non-XML signatures).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://shibboleth.net/community/advisories/secadv_20250313.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Shibboleth Service Provider version 3.5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31335");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:shibboleth:service_provider");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("shibboleth_sp_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Shibboleth Service Provider");

  exit(0);
}

include("vcf.inc");

var app = vcf::get_app_info(app:"Shibboleth Service Provider");

var constraints = [
  {'max_version' : '3.4.99999', 'fixed_display' : '3.5.0.1'},
  {'min_verison' : '3.5', 'fixed_version':'3.5.0.1', 'require_paranoia' : true}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_NOTE);

#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213290);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id("CVE-2022-46175");

  script_name(english:"Atlassian Confluence 5.9.1 < 7.19.29 / 7.20.x < 8.5.17 / 8.6.x < 8.9.8 / 9.0.x < 9.1.0 / 9.2.0 XSS (CONFSERVER-98301)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-98301 advisory.

  - JSON5 is an extension to the popular JSON file format that aims to be easier to write and maintain by hand
    (e.g. for config files). The `parse` method of the JSON5 library before and including versions 1.0.1 and
    2.2.1 does not restrict parsing of keys named `__proto__`, allowing specially crafted strings to pollute
    the prototype of the resulting object. This vulnerability pollutes the prototype of the object returned by
    `JSON5.parse` and not the global Object prototype, which is the commonly understood definition of
    Prototype Pollution. However, polluting the prototype of a single object can have significant security
    impact for an application if the object is later used in trusted operations. This vulnerability could
    allow an attacker to set arbitrary and unexpected keys on the object returned from `JSON5.parse`. The
    actual impact will depend on how applications utilize the returned object and how they filter unwanted
    keys, but could include denial of service, cross-site scripting, elevation of privilege, and in extreme
    cases, remote code execution. `JSON5.parse` should restrict parsing of `__proto__` keys when parsing JSON
    strings to objects. As a point of reference, the `JSON.parse` method included in JavaScript ignores
    `__proto__` keys. Simply changing `JSON5.parse` to `JSON.parse` in the examples above mitigates this
    vulnerability. This vulnerability is patched in json5 versions 1.0.2, 2.2.2, and later. (CVE-2022-46175)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-98301");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.29, 8.5.17, 8.9.8, 9.1.0, 9.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46175");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'min_version' : '5.9.1', 'fixed_version' : '7.19.29' },
  { 'min_version' : '7.20.0', 'fixed_version' : '8.5.17' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.9.8' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.1.0', 'fixed_display' : '9.1.0 / 9.2.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);

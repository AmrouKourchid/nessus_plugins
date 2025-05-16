#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192703);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2023-36478");
  script_xref(name:"IAVA", value:"2024-A-0175-S");

  script_name(english:"Atlassian Confluence < 7.19.20 / 7.20.x < 8.5.7  (CONFSERVER-94843)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-94843 advisory.

  - Eclipse Jetty provides a web server and servlet container. In versions 11.0.0 through 11.0.15, 10.0.0
    through 10.0.15, and 9.0.0 through 9.4.52, an integer overflow in `MetaDataBuilder.checkSize` allows for
    HTTP/2 HPACK header values to exceed their size limit. `MetaDataBuilder.java` determines if a header name
    or value exceeds the size limit, and throws an exception if the limit is exceeded. However, when length is
    very large and huffman is true, the multiplication by 4 in line 295 will overflow, and length will become
    negative. `(_size+length)` will now be negative, and the check on line 296 will not be triggered.
    Furthermore, `MetaDataBuilder.checkSize` allows for user-entered HPACK header value sizes to be negative,
    potentially leading to a very large buffer allocation later on when the user-entered size is multiplied by
    2. This means that if a user provides a negative length value (or, more precisely, a length value which,
    when multiplied by the 4/3 fudge factor, is negative), and this length value is a very large positive
    number when multiplied by 2, then the user can cause a very large buffer to be allocated on the server.
    Users of HTTP/2 can be impacted by a remote denial of service attack. The issue has been fixed in versions
    11.0.16, 10.0.16, and 9.4.53. There are no known workarounds. (CVE-2023-36478)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-94843");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.20, 8.5.7 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36478");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'min_version' : '5.3', 'max_version' : '7.16', 'fixed_display' : '7.19.20' },
  { 'min_version' : '7.17', 'max_version' : '7.17.5', 'fixed_display' : '7.19.20' }, 
  { 'min_version' : '7.18', 'max_version' : '7.18.3', 'fixed_display' : '7.19.20' },
  { 'min_version' : '7.19', 'max_version' : '7.19.19', 'fixed_display' : '7.19.20'},
  { 'min_version' : '7.20', 'max_version' : '7.20.3', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.0', 'max_version' : '8.0.4', 'fixed_display' : '8.5.7' }, 
  { 'min_version' : '8.1', 'max_version' : '8.1.4', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.2', 'max_version' : '8.2.3', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.3', 'max_version' : '8.3.4', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.4', 'max_version' : '8.4.5', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.5', 'max_version' : '8.5.6', 'fixed_display' : '8.5.7'},
  { 'min_version' : '8.6', 'fixed_version' : '8.6.2', 'fixed_display' : '8.8.1 (Data Center Only)' },
  { 'min_version' : '8.7', 'fixed_version' : '8.7.2', 'fixed_display' : '8.8.1 (Data Center Only)' },
  { 'equal' : '8.8.0', 'fixed_display' : '8.8.1 (Data Center Only)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

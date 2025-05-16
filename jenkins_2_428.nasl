#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183316);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2023-36478", "CVE-2023-44487");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"JENKINS", value:"2023-10-18");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2023-B-0083-S");

  script_name(english:"Jenkins LTS < 2.414.3 / Jenkins weekly < 2.428 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.414.3 or Jenkins weekly prior to 2.428. It is, therefore, affected by multiple vulnerabilities:

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

  - The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation
    can reset many streams quickly, as exploited in the wild in August through October 2023. (CVE-2023-44487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-10-18");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.428 or later, or Jenkins LTS to version 2.414.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
  { 'max_version' : '2.427', 'fixed_version' : '2.428', 'edition' : 'Open Source' },
  { 'max_version' : '2.414.2', 'fixed_version' : '2.414.3', 'edition' : 'Open Source LTS' }
];

var app_info = vcf::combined_get_app_info(app:'Jenkins');

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

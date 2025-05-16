#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235662);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-27533");
  script_xref(name:"IAVB", value:"2025-B-0071");

  script_name(english:"Apache ActiveMQ 5.16.x < 5.16.8 / 5.17.x < 5.17.7 / 5.18.x < 5.18.7 / 6.x < 6.1.6 DoS (CVE-2025-27533)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.16.x prior to 5.16.8, 5.17.x prior to 5.17.7, 5.18.x
prior to 5.18.7, or 6.x prior to 6.1.6. It is, therefore, affected by a denial of service vulneraiblity:

  - During unmarshalling of OpenWire commands the size value of buffers was not properly validated which could lead to
    excessive memory allocation and be exploited to cause a denial of service (DoS) by depleting process memory,
    thereby affecting applications and services that rely on the availability of the ActiveMQ broker when not using
    mutual TLS connections. (CVE-2025-27533)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.apache.org/thread/8hcm25vf7mchg4zbbhnlx2lc5bs705hg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f714d45");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.16.8, 5.17.7, 5.18.7, or 6.1.6 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27533");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"stig_severity", value:"I"); 
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl", "apache_activemq_nix_installed.nbin", "activemq_listen_port_detect.nbin");
  script_require_keys("installed_sw/Apache ActiveMQ");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'Apache ActiveMQ', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'min_version':'5.16.0', 'fixed_version': '5.16.8'},
        {'min_version':'5.17.0', 'fixed_version': '5.17.7'},
        {'min_version':'5.18.0', 'fixed_version': '5.18.7'},
        {'min_version':'6.0.0', 'fixed_version': '6.1.6'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);

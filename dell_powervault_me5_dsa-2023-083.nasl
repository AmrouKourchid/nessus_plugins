#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(179606);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/10");

  script_cve_id("CVE-2022-0778");

  script_name(english:"Dell PowerVault ME5 OpenSSL (DSA-2023-083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote storage device is affected by an OpenSSL vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell PowerVault ME5 installed on the remote host is prior to ME5.1.1.0.5. It is, therefore, affected by a
vulnerability as referenced in the DSA-2023-018 advisory.

  - Dell PowerVault ME5 remediation is available for an OpenSSL vulnerability
    that may be exploited by malicious users to compromise the affected system.
    (CVE-2022-0778	)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000209966/dsa-2023-083-dell-emc-powervault-me5-security-update-for-an-openssl-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1f594a0");
  script_set_attribute(attribute:"solution", value:
"Update to Dell PowerVault ME5 version ME5.1.1.0.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:powervault_me5012_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:powervault_me5012");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:powervault_me5024_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:powervault_me5024");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:powervault_me5084_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:powervault_me5084");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:dell:powervault");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:dell:powervault");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_powervault_slp_detect.nbin");
  script_require_keys("installed_sw/DELL EMC PowerVault");

  exit(0);
}

include('vcf.inc');

var port = get_one_kb_item("Services/udp/slp");
if (empty_or_null(object: port ))
  port = 427;

var app_info = vcf::get_app_info(app:'DELL EMC PowerVault', port:port);

var affected_models = ['ME5012', 'ME5024', 'ME5084'];
if (!contains_element(var: affected_models, value:app_info.Model))
  audit(AUDIT_HOST_NOT, 'an affected model');

app_info.parsed_version = vcf::parse_version(app_info.version - 'ME');

var constraints = [
  {'fixed_version' : '5.1.1.0.5', 'fixed_display' : 'ME5.1.1.0.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

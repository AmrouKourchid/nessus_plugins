#%NASL_MIN_LEVEL 80900

include('compat.inc');

if (description)
{
  script_id(197183);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-38545", "CVE-2023-38546");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"TensorFlow < 2.14.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of TensorFlow installed on the remote host is prior to 2.14.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the release notes.

    Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/tensorflow/tensorflow/releases/tag/v2.14.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TensorFlow version 2.14.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tensorflow:tensorflow");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tensorflow_detect.nbin");
  script_require_keys("installed_sw/TensorFlow");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'TensorFlow');
var constraints = [
    { 'fixed_version':'2.14.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
        

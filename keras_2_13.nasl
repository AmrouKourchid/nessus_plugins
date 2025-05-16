#%NASL_MIN_LEVEL 80900

include('compat.inc');

if (description)
{
  script_id(205011);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-3660");

  script_name(english:"Keras < 2.13 Arbitrary Code Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an Arbitrary Code Injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Keras installed on the remote host is prior to 2.13. It is, therefore, affected by an
arbitrary code injection vulnerability in TensorFlow's Keras framework (<2.13) which allows attackers to 
execute arbitrary code with the same permissions as the application using a model that allow arbitrary 
code irrespective of the application.

    Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.cert.org/vuls/id/253266");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Keras version 2.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3660");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:keras:keras");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("keras_detect.nbin");
  script_require_keys("installed_sw/Keras");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Keras');
var constraints = [
    { 'fixed_version':'2.13' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
        

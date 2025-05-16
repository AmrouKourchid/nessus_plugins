#%NASL_MIN_LEVEL 80900

include('compat.inc');

if (description)
{
  script_id(197897);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2022-35935",
    "CVE-2022-41880",
    "CVE-2022-41884",
    "CVE-2022-41885",
    "CVE-2022-41886",
    "CVE-2022-41887",
    "CVE-2022-41888",
    "CVE-2022-41889",
    "CVE-2022-41890",
    "CVE-2022-41891",
    "CVE-2022-41893",
    "CVE-2022-41894",
    "CVE-2022-41895",
    "CVE-2022-41896",
    "CVE-2022-41897",
    "CVE-2022-41898",
    "CVE-2022-41899",
    "CVE-2022-41900",
    "CVE-2022-41901",
    "CVE-2022-41902",
    "CVE-2022-41907",
    "CVE-2022-41908",
    "CVE-2022-41909",
    "CVE-2022-41910",
    "CVE-2022-41911"
  );

  script_name(english:"TensorFlow < 2.9.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of TensorFlow installed on the remote host is prior to 2.9.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the release notes.

    Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/tensorflow/tensorflow/releases/tag/v2.9.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TensorFlow version 2.9.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41900");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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
    {'fixed_version':'2.9.3' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
        

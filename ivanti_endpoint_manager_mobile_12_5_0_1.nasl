#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235860);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2025-4427", "CVE-2025-4428");

  script_name(english:"Ivanti Endpoint Manager Mobile 12.5.0.x < 12.5.0.1 / 12.4.0.x < 12.4.0.2 / 12.x < 12.3.0.2 / 11.x < 11.12.0.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Ivanti Endpoint Manager Mobile, formerly MobileIron Core, running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager Mobile, formerly MobileIron Core, running on the remote host is 12.5.0.x prior
to 12.5.0.1, 12.4.0.x prior to 12.4.0.2, 12.3.0.x prior to 12.3.0.2, or 11.x prior to 11.12.0.5. It is, therefore,
affected by multiple vulnerabilities:

  - An authentication bypass in the API component of Ivanti Endpoint Manager Mobile 12.5.0.0 and prior allows attackers
    to access protected resources without proper credentials via the API. (CVE-2025-4427)

  - Remote Code Execution in API component in Ivanti Endpoint Manager Mobile 12.5.0.0 and prior on unspecified
    platforms allows authenticated attackers to execute arbitrary code via crafted API requests. (CVE-2025-4428)

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9992ac53");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Endpoint Manager Mobile version 12.5.0.1, 12.4.0.2, 12.3.0.2, or 11.12.0.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-4428");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mobileiron:core");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:mobileiron");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mobileiron_core_detect.nbin");
  script_require_keys("installed_sw/MobileIron Core");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'MobileIron Core', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        { 'min_version' : '11.0.0.0', 'fixed_version' : '11.12.0.5'},
        { 'min_version' : '12.0.0.0', 'fixed_version' : '12.3.0.2'},
        { 'min_version' : '12.4.0.0', 'fixed_version' : '12.4.0.2'},
        { 'min_version' : '12.5.0.0', 'fixed_version' : '12.5.0.1'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);

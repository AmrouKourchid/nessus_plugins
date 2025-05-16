#TRUSTED 6a8e57d6535c9dacb5119b3e9234c6636157781c5e068964c7f9fc090ee0cfc3b89a384f01600b2ff34c12f6413288dda55824ddf799b0e0dcc50b8d9c5aa26e823862e5b6829102f932bae6cb330a8e923d1ffb6754284cdc1be2b0198a392a1c7a0a5d30a636faefc73d4a9a0b1a00a9b2be17eae6806be7942280b9a7049b64365018977a07a75157fc4a721bd082a4e2923f8c422f989bb345baea72003906cf88231ed24b107274aecabda2d1cdf87cec9192c2ba9aa61ab88fab1753f01854c315e179c723da04ce3141d33e0a3f062066d8acc596d507cf5a0e0ce464bd9812f0651d098e8e0c03d3c349085151ef296bf6523ea395c5aade9b7c7960be050017cc9311a97338b85b4e003d73f9791c2406cd4b196b3c88adc780ea7488e68f533e3f4f03bb560b3922d9853c3c0fc1d22116d03e1b3e224b15079352774c08eca43048b8b208f9e583a909553dd5d383fce89022d884b2053f6aa2cfd0714df752ce18e026da394787e05ce7fe01f0693d6d9b3be19ae9b8eb172beccaebc65b02dfd081c6fc370555628c2ce721b43f79b430ffa7d727ba2e22aa3cfb81f78f66ce5d3a634cf3615d1ea7617b1777990b7af248c39d8e8a9f16b52414730e251f777a2e0599ffc7dcd946f2f93d470d6c7e76a3d330550063417b005c8f080c7f5bfed94a0e32c3d0f368183c7d143af40b237602fa1d659d101fbd
#TRUST-RSA-SHA256 aeb8a740cf01dd97b6e06cad591a3ad8f4ec059ec007b9be3b69b92c979dfa844cf413c79e567381b9a9aa58fd436a88ee471760aa43e38dadb2355470a8653cb20b785c9b8799f69fd30f06fa6fed9729dee3f4edec88765244183ab2c7820581bbcdfabb8333ae356166740241f92780c21e85633bd4a97d24adc27a47f7f74c7f262738565ec0ebed1635467e7f1e010e0b6d8d8d290634d48b7c0be1ea3a6cdc743709f64bd852c49d368d556ff357795a79535781562730a142a5807bb51fdbcc2c80646fe143e7cdb71c54cc13bc2b92ba0d27294813176299a3b6a4e422c638ca92f544193e1347ba6c9e978818f19a2e37ab8cd227e9c97f058d5ed6bf4559e947857b9fc5d848f849185f664bc9a0528a1aa5f41c3032c573eeaf702ebe52254fb08a6f31a4bf75bcfc98803e81400d8ba15902192417d1924549366c7519ca69e67fed0e5f4e94dda4585b04926e2e9d57e15337a95fb641585c9fc3652207e243ec844409dbf30e320d566fbbd6428d1cc468158a6d439ec26b2fe66e22f7ff75f434a2efff5c07563fcc8036468fef09b1a64806dbccf505f6eb96e06dfbb82c1a4c1f5a0b9846500471c454211af66c3a6dea216e9dd9cb1d79b5daf8886577771842b34ee475452785059aae60ac4d4db6d65230bcf8d1e857688ec6f1f74adc88a3eef8947099b9ab4317a6455d447f1de96a2a17da815903
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153258);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2020-27131");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu99974");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv79824");
  script_xref(name:"CISCO-SA", value:"cisco-sa-csm-java-rce-mWJEedcD");
  script_xref(name:"IAVA", value:"2020-A-0535");
  script_xref(name:"CEA-ID", value:"CEA-2020-0136");

  script_name(english:"Cisco Security Manager Java Deserialization (cisco-sa-csm-java-rce-mWJEedcD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in Cisco Security Manager due to insecure deserialization of user-supplied
content. An unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-csm-java-rce-mWJEedcD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ead11b1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu99974");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv79824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu99974, CSCvv79824");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27131");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_manage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_security_manager_win_detect.nbin");
  script_require_keys("installed_sw/Cisco Security Manager");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

# get_app_info wrapper converts version string to <version>-SP<service pack>
# for ease of writing constraints
var app_info = vcf::csm::get_app_info();
var constraints = [{'min_version':'0.0','fixed_version':'4.22-SP1'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
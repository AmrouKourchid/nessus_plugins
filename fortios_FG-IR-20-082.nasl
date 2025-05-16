#TRUSTED 647f401973a393d072952dc1e886879e87379e54992ac9c29f5f2454ddb0503477a6b80f299b06090f539671adbc1ab5ff7a75e92663bbd2db1457a4802d57d80bd2f0ef2beb94e874f156e019b4a15e4d449c9622578540f3f6e83a4a2e8a7e0523c731ed4eeb2ba8d7c0d8da3bce95df7b62e4c13db0fe0cf3919122d15f1b01d5073baa253e02f2fe7ebc744a37c680342e2374a03396e7cb8855645fe82b8b51fa5d9af470f086753a75be365b18e773f79c8439c34292e7062cfa74d43987d9c6ad2c9deaa4cb41a70fda8bb67931c9bc6b02d84b924a20a541be556def3685f96d403174742f3df6773a00400ad74dc4dc8dd14ee30d35d0548c1891d151621b620f2abe41a8773bc98a4ba27cf270c52689eb3d8250f600b2e334e335c738b327a408c34abebe50017a2f4da38f75cf5eee26bcd59dee65c7a940ec67c32754abb6fb6290a18c0a3afd0bfe2536bd3145de8a1d94253e67154e99354bf84a1f095957a1e89abd7c1740b06a85afa7beb5993b59387581296a151a3c6e469fe00e98a1fcf30ccdf417f5711dfbbb59ccc091bb30ffb6b899b1e22ab5d33485d915f66a2c74b9910392be0301c65cb0763cf8ace3d95d8be6a63f42eb0ba3a98a3bcb0d6a31c135eb8d5d0d3f545d80b5df8ef1236aa3960c39d8acfe668a410fd94970ff77ca74555e0f459d6815bc4b5ded78033ea54a372b501fa886
#TRUST-RSA-SHA256 4e6f825f0c6c2884704fd1b0946eefed287abb29cd412b4f3ec8388b771a210cd0b7649a882c8d29a97bc830ab8633c18049e3ccf5023e9b9d3edc78da6674fe59f5aaf7282121722535f08862b7d40da9804bb69c69fc9ce7637c29cd5531ede6b6cb16271e031e29c04c563e6c22eb90d7b1e55b38bfa321635c7af36087daaa3c4f38c09aa25ef5a80f11108c8eecbd16ff9f11722bd59faac630757fc805cd35f4fc3dc7df656f29e58fbad622b7475e8303e13117ae7f4a4b461218a0b6fe435aac0e707744ecc8c73f906de87d1e8a0140dd3425643b4367175fa8b41d47a6c91ae53f48c77d74ee2c3fcf2f72166b4311e7f64e52c0439b760a7b177442c573294900c717201897144f6b17792ba679e03c476d6f3284df3dc29aa37bcd839b721d6935ad526c3464f1491b9ffa1e06f7d84e2f8c2ca6f67d733b4bfa856165ba884324b0c87df241e2be8d93a5b2a75fcb79c25aa02b2f5c5b6ab30ef9d6868f3e77632879d0b117a5fdf001ba71b51a05c82a05ffc309be912c1c3bee7b9e849e075488213538a2df5e447eea6bad22f434906ec5b3f99f5bd6ca3cb621fea07cf38d36a588db4aa32ca710636b8e0dd77aa271a5b14371df6ddede14f6e436e00a23345bd904ffd9714ff0b7fef5a24671f026a93cd313bfa522bd2b5823600b30e40ec36882697e1ae331b8100d03821df981e3d6da927db67173
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141567);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2020-12819");
  script_xref(name:"IAVA", value:"2020-A-0440-S");

  script_name(english:"Fortinet FortiOS < 5.6.13 / 6.0 < 6.0.11 / 6.1 < 6.2.5 / 6.3 < 6.4.2 Heap Buffer overflow (FG-IR-20-082)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.13, 6.0 prior to 6.0.11,
 6.1 prior to 6.2.5, or 6.3 prior to 6.4.2.

It is, therefore, affected by a buffer overflow in the Link Control Protocol that could
allow an authenticated remote attacker to crash the SSL VPN daemon and could be used to 
execute remote code.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-20-082");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.13, 6.0.11, 6.2.5, 6.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12819");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin", "ssh_get_info.nasl");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('hostlevel_funcs.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version': '0.0', 'fixed_version': '5.6.13' },
  {'min_version': '6.0', 'fixed_version': '6.0.11' },
  {'min_version': '6.1', 'fixed_version': '6.2.5' },
  {'min_version': '6.3', 'fixed_version': '6.4.2' }
];

workarounds = [{config_command:'full-configuration', config_value:"set tunnel-mode ((?!disable).)*$"}];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, workarounds:workarounds, regex:TRUE, not_equal:TRUE);
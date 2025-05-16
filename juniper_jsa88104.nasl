#TRUSTED b2fee7b02aef91c38cab7834be5fc2a7bab000c965512534582356256adda6174a5d766782f796b985b1d3691aebe80a7c6add2102a691a0bc8f0d2a7a579d256f8afbd2ff5515837d5354dbfda6a8e4017a50ae0f09e9041af3c4857f389ea8558baabf007f381383aa582ba62891cce3e0c3c580b77e449747867b2001479f954c669db583f9aeb168dd680196bec05eef6ffe493dcfdbcf629509df14ff1f7efc8bef4915a5939d189c2db5299f41c7a4750082853afdff569d71d969adc580fac11ffb3a0ef074953c25aee34751ea1b35f4334f269ce8ee82adaff6350677f3fc8518da4db6ff3b55f9db7d112c2e92eb5fb0a04f630c523c330ec439c4c3c3841e2dbb008da147786e7d54bd0611fe1ee8e25ff16f3bb105652c332bc4b9695191e2e2125060f8f0288e5a0584d932d191252172d94aaf52e496d22cc1fa077b41c06c8369c715c214a535f18a07dbe4527d5d0d52b48c832e59921170a744c2a5453c5bc5f88e7cfe7f9abd843b064eb8eca147f030f6386c69eb35d3a7d2ab79eced4942b91f43dc6c98d72def7b44332661ff9825a8f962c2634058c5ff0e35ca5162bd726b4c9c1bff854ab4525563860885948134822106b336ba0059b72a4be3ae4ea919efbfd87d626eddf927b736d601c80ae5625a075f8681650ecd047fffc25ca7f4144a291281d3684af366c2e82b1c73572bf8505874af
#TRUST-RSA-SHA256 6f1b909579d8c25d3a371e06aa64838fbecc39c1eebf3c9b34eff4e9cfbe6150ca011e376846edece5d026e6347d557e82976d5ebe2d50dae89166b681f724430997374a565512c01b9d40860ec623057952b1bc463946ae9be17ce57962405ab7ead51a11acfab21f5ac6a05205b75944503d4e8dfd78d9376f45551c0b75be0947092654d393149400c0ff0eebae4f67597f672952746683b89ab49da90982258cb110e7a873cf5fc754cb2d3b324e69f3dc6f53771b48b755524da5b84c6c71ed7f5fe39bb4dc3f8b7bc16b6d09c082fea3e7ee4c08d95a611d75643340574e89b646ebd8489c5c93c36777b057357aecc47d3d7b9d4d8873f4159cfe687938e9b9b59f18619f39ecd5bde052d2a47ef170a975218e99e7dec14ed1e6b72fe6d23757cfc74ea52ff44d422f0ecbe5cb1510be7047a281c4bec44336485250fa34d3f29dc135e4f1a5686ff60451396261120dea1015089fbdb5fad3c0d1622a3f6c7ffa53f1caec48a5ac7a9d97ed9a855f4b3cecf2e89391496ea610a4a7289706e2d5887c0111630573d0abdb76dd142831478d53d400aa1025d5cf36db24afffc7d62f9834fef543ddef1cd461e5294b85f297ccfb04050dfcd102d58cfc8a69590901dde72fed1f39b781f15f2f85e3db95f790a8b970e1a63f364a487f570b3c02268c0eb236cc2554d607905eef3643859dc50e4a8e64d75925e77a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210408);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id("CVE-2024-39527");
  script_xref(name:"JSA", value:"JSA88104");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88104)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88104
advisory.

  - An Exposure of Sensitive Information to an Unauthorized Actor vulnerability in the command-line interface
    (CLI) of Juniper Networks Junos OS on SRX Series devices allows a local, low-privileged user with access
    to the Junos CLI to view the contents of protected files on the file system. (CVE-2024-39527)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-SRX-Series-Low-privileged-user-able-to-access-sensitive-information-on-file-system-CVE-2024-39527
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e04a2b5");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88104");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.4R3-S8', 'model':'^SRX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S5', 'model':'^SRX'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S4', 'model':'^SRX'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S4', 'model':'^SRX'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-S2', 'model':'^SRX'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R2', 'model':'^SRX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);


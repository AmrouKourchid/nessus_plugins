#TRUSTED 253381fdad822571d7394ee07b2d1ff4e02951ba8254ce6c4cea5b8b79aa7e6daacc666f42a42dc107c85a24d2e30d52b4db31b60cd523e30615d6285fee02afc51697c49f30e2b9da71e4e41435386e50890528234804b42792fd45c63dfa717077cfb56c7eb221b47a76bf848d1b9d4bcc5957c50a5ec9abd2f4ff20223a46ca36a435d2c628e249b936eb35e653cb79ef07550f4826fec60e1a6602f20fe697db60019f19b0c61865aeb0eccb8538d5ecdd5ae319dbf19385e7c67852aa9840176edb7a906db7558b1ddc7b2a9ba7cf835fbf8809b894e09a819127f25835bb94930c0d84b8cb96c1858db0bd5640c4eb9b950caf68bd45355a17e44891a16d1271c318d3d32d59578446cc3d62061c4d70dfc243e85de2eaaabcf75252d1614f280176004b22ec323614b4523044a6fc1ac5c29a9ce7b27c58462450c76797327c68588b9f29ee83d911c8bf33ae95b24d0df8d3fff8b49a54e9ea19433a42c41660f4166a59370da4cc65912ff57bf64171331b78f7a88c794043151001a4d9f3f6d23e01c39a2746c7fb606b849d78b09b4d5c3705a9726d46dbce119cc73de52cf0c3a677838a5ae51d340aa66a6f6af6952b9ec0c1023d8e26258ac5c9eebb66dc32e4dc2406d61da55d3f813408bc392e451a98c8daeaf1d53951d2ffbb70c3df408458608bf3c8f846a9de372100cef8912931845e314392b416a2
#TRUST-RSA-SHA256 4dd6dd90b60c31e4e55fef4e07d1334dd2b3da5da98312127c51a316b9cc08b95a316048bf78cbed6c55d3f60c30d3a872d7ed297c2f0fd366ab020549d21a4d45f0a5327ba3e9d3354999eff86f925597163c409dce2f4c8ca322f803dfdf28e0609a81fdcee44f296f82af583b28d81781a6e2b9d8dcee1f6e8aa38f2b1075a28411375121cf53c1ae6ae53f942d43855543a1ffa62c2ae5a62f7c0fc33685bad09093e3d204a1194f7f7cdcf6035778ec2c2545a945226e7fdd9eddba0e4d4325f4209ccebf0f0c55a6b1a62670041026b477e6f1b06d0d8c2e1a636346468e90c2e6488888029de4ba6e477af5470b791a13997ce6c881ef76ef4a60826c67fe7874ff3ef149b9329e66ee4d857ea9ec94ee7daab63371d084b00d9d603c61d64030bb81c630e492df68d5f549ca2262d3253043dd412a7430134f0a5be200f30bded620812ef38aeee6ef109e6769899132250f07d891b02ef8dea23c202b5e239cfa1ec410d3d7fab0e206742322a56f23290ba58de035c22102969a567d60a6f188f7eac7f1542239957872cc3169df9aa630285b63021067f74243fcdb2202464c753c7dcb22329ecbadcce57bc3756eebe21b115a2b84a7141e5af7f1deab41273bb0e8183692d08fa363a567d738d88b6a5ff2986b422d62da515940fe10ce8da8e7ca16d4d6e902e00a3c37e860e4b928997901a34f913aeb3bbb
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144978);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id("CVE-2021-0215");
  script_xref(name:"JSA", value:"JSA11105");

  script_name(english:"Juniper Junos OS Denial of Service (JSA11105)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11105
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11105");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11105");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0215");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^(EX|QFX|SRX Branch)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'14.1X53',	'fixed_ver':'14.1X53-D54'},
  {'min_ver':'15.1X49',	'fixed_ver':'15.1X49-D240'},
  {'min_ver':'15.1X53',	'fixed_ver':'15.1X53-D593'},
  {'min_ver':'16.1',	'fixed_ver':'16.1R7-S8'},
  {'min_ver':'17.2',	'fixed_ver':'17.2R3-S4'},
  {'min_ver':'17.3',	'fixed_ver':'17.3R3-S8'},
  {'min_ver':'17.4',	'fixed_ver':'17.4R2-S11'},
  {'min_ver':'18.1',	'fixed_ver':'18.1R3-S10'},
  {'min_ver':'18.2',	'fixed_ver':'18.2R2-S7'},
  {'min_ver':'18.3',	'fixed_ver':'18.3R2-S4'},
  {'min_ver':'18.4',	'fixed_ver':'18.4R1-S7'},
  {'min_ver':'19.1',	'fixed_ver':'19.1R1-S5'},
  {'min_ver':'19.2',	'fixed_ver':'19.2R1-S5'},
  {'min_ver':'19.3',	'fixed_ver':'19.3R2-S3'},
  {'min_ver':'19.4',	'fixed_ver':'19.4R1-S2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
# https://www.juniper.net/documentation/en_US/junos/topics/example/802-1x-pnac-single-supplicant-multiple-supplicant-configuring.html
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
  {
    override = FALSE;
    if (!junos_check_config(buf:buf, pattern:"^.*dot1x\s+authenticator.*"))
      audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  }
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);

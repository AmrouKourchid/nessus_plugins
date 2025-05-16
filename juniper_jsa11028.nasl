#TRUSTED 8d6464fc69f767ba32dcce1b6250def090a3fc647f4dd391d64b2cdc9d7236b6b7603beec6da1c9bfded1c70bf55af1c6ddb08e75b805fbc19733bc4c651fa6a76583c8a6b9381fcbcd1219c9e107e6a9caa888797c76893fc4ceb851b47956b9e68aa824667c44b74d1bae56e57ef4085741701f4830398b4a0d61647741546cbd5e1587df505b6a54789420ed308658ba14b7fdef0caa64e296168bb0288d3208fbb03fe89c4ab15b2398a98af0a0f854e11bae6df8fb3e3f719663f429158620420b987ea407fae9e88ac81404ec26ee78fb6bcec657330729a12d408f3ff22bde137ee22f8f29e0ae25fba8d01dfe73579765c6e8b9628b803967d002bf386c0ea23d8e2ecbe2f20ef04cb51f55b1dec437aa35c8ff17d3a1c63241b0f468e0865ea9a0beece9ad423183a1623e00a47b680addf7ba1a5f131f669404dc7cd4a50828933501042a2ed4714178bbbad08753a2160933ee676c43c016e173d1d349053d6f4a87c64413de0b35a9196f8086acb871cabca0ec4280f7e7ca32b2ed174b64ce8ea423f2a7094106c3b951d3dd51bcf4dbfc704699e0519dbbbdcba57f6fa9257a8d25aa6b2eb681f6d03336e05ad8e7bbb79b43501ee62c978d7ea7076ff2d09ebe965ce90342293b187293dce6458bf6677162112fee0b795b25d45fc2e2facea57c5bea3990fe3d03a5b4cea4985ebe92dd515369e4ddf1e5c
#TRUST-RSA-SHA256 76fed0f3803eaf190d1d94a4b571da052483e2a5ad550ecb8a227642ba5c50537276a1d2be152e1f90d2931f216ab15ab595caa3d4959724ca3b92726b0db60ddd3ec86af5a5cf29cab921bf136109ed8ceb86a7185b619bacf009f859bba89e9c775c5bfe15259fcd5825743a49af58ecd70318150e86bedecdbbfac434949472c17b3d260563bde90f7f3b713c0331d500b82293b77d6073598e378a255e7359b14df79f7288946949fab463c1e908fc0188bd9baa10f5a509bfc67bc1fd7821d7e3cc8db5bf0d4ac71ea7819edec02836daf036284d20879ad47935f3652b3dec93448ebbe2b6b1c29072056ac3ab89a2633f2f21b5d798137ad24585e42e0ae8e20bb1821c801de57a5c0e1edf77f94cc38c93171a4d7ab0dabf2ef54ae018ad5fe3eb3bdb0e1233c79beba8f0d71442ebdc47d6556f1a85b9bc9191ad5e0be4f865b708b54fa99f805ea9143a71f505535dbeed637d566cb27a52f2c9c6afa4573a0da6549ec71ead9661fc026a30176d6738476723d0416e4f59b88c6bf6d6ab1c546a10e1fd5dea7a82519c3090c5c54f1ee5e895d4e49bd0eea86f68c56bda0de156d975f844a87629731e3ca4d13f229b5f50b1fb63a053b4133ee3a372323f73002e20dbf19c31f8d6f4f57ec2c47234535bf2c38393f7a5cd8fe6fc1083cfe2736baa2b3ac92690c85a41207590683aeefdcb995f6ece13b7306e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140586);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/18");

  script_cve_id("CVE-2020-1645");
  script_xref(name:"JSA", value:"JSA11028");
  script_xref(name:"IAVA", value:"2020-A-0320-S");

  script_name(english:"Juniper Junos DNS filtering JSA11028");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device is vulnerable to improper input validation.
When DNS filtering is enabled on Juniper Networks Junos MX Series with one of the following cards MS-PIC, MS-MIC or
MS-MPC, an incoming stream of packets processed by the Multiservices PIC Management Daemon (mspmand) process,
responsible for managing 'URL Filtering service', may crash, causing the Services PIC to restart. While the Services
PIC is restarting, all PIC services including DNS filtering service (DNS sink holing) will be bypassed until the
Services PIC completes its boot process.

Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11028");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11028");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

# This issue does not affect Juniper Networks Junos OS releases prior to 17.3R2.
var vuln_ranges = [
  {'min_ver':'17.3R2',   'fixed_ver':'17.3R3-S8'},
  {'min_ver':'18.3R2',   'fixed_ver':'18.3R2-S4'},
  {'min_ver':'18.3R3',   'fixed_ver':'18.3R3-S1'},
  {'min_ver':'18.4',   'fixed_ver':'18.4R2-S5'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R1-S5'},
  {'min_ver':'19.3',   'fixed_ver':'19.3R2-S3'},
  {'min_ver':'19.4',   'fixed_ver':'19.4R1-S3'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
  {
    override = FALSE;
    var pattern_w = "^\s*set web-filter-profile ";
    var pattern_d = "^\s*set dns-filter-template ";

    if (!junos_check_config(buf:buf, pattern:pattern_w) &&
        !junos_check_config(buf:buf, pattern:pattern_d))
      audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
  }

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (!isnull(fix))
{
  junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
}

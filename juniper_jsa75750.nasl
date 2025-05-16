#TRUSTED 586e55aca4d90b6a8db7a78615da6f7e97ec66c488b29d9b24d6daa26a31cf66f32d5e064d98f0160582bf204c8d6cef9efb0bb9db5f000d6c018ded832f4d5cda5676bcfdfc942039fe7df14c63306f64815b594a2a4812e20c890d75663fba6826421f9fca552f03313cf3264cdee414507155c1ad837db0ca708d2b8f6b5bc72ee574e1160039ab1ff0228d01aeb5d6ef36dc33f1e4bc6ba7164cc26b602e216bb40af09e1d1ab08ade400f36d577c39179996a78d671dcaeb335c549299bff4f9ca3663375930fae72b64a958c88b7d7fd4c776249fcfcdbbd6b1fd759523e9936cf14bb845d48cd574a33bcf9caae636bc731e7a03dea5c7743151be8dce77b241a948ad3db75316edabd02fa756b2c4ba8379388bb7bbf14726583244599d88c54494de49c7c02d6d0e49d3e25828af58401f2b5896dab3406b5384f834624b7d826bf7c24794e4bf8536139b698b8564fb92deee80a387c9e535b0b24d24635a13ccc75fde677adf76fa2d640ddbc4edaffa5245286e8a57e29fdb9d8877e5bdbe16d736651ef97408219f4089e5b3c74933ec2c2e5f9564bc5603efe299b56b516b4fbb152b34ce409df1e096d9af3b2dc442cae6f8116255c858f641f61530ad54c6a5e09b958da6be5fc60080a5fc143679400b2abba44aa2620c97f0bd3c05201a46b261a0d6fad6ec13a26db55c9ce3f1bcb0d9441542144a51f
#TRUST-RSA-SHA256 93a36cab0b39988ab0116bc11082c9e3e5ac088e52a628eab8e33660dfcc1f20e7037ebc22da4aed8c02e2bb3c2c54a9d87fcf1a99b8c13f5c16d02024686271fe1ab62d4c86504ceac3662de2e428da604cbd9ccec65a2f3424999f79faa5801dbfa8c52bac479dea7649437f1b8aa85168d0e7bc1b3c4f6a65128901f848831549081f18416611e62de130fec938e25c6cd193e70cb7fe2b652b531205db1537cbf087597da0b92d5389a1a108a2fa0a9e6efdd03fd5678759704b42c82b3fda6e7789a0812ac336d5ed26bf89b72f0c68972f29c7536a9f363ffb9e6f31639138cdce6d0c1ed877b461f89944ec91a535d9ee020d48af527628743bbd8fe03d7c49e52c40bf81ef953e0a7fae40222192253acfeba86739859c25fb9ed9b132668d014d4c478efa26681a52b85ca0c762f93ca5c78ceddbd2bdf3b7ee357ae3ae809166a224f7af1c33c8ec050ed8bc8a17fb163e379825997ad561d9b60eca0bbc6f96effcb790ee0cf26e010faf524073a9af4e71596e2363c3a33ae58274746457aa232c7c4bd9c4397449035ab1442cb771544dd3570c91270cba4e91efcf3b38b1f720dd6c05497c01aa5bb10a97d61c4236cc4b5229d38805181047ded7b5c2f03c8e39b0609ae69be9c834f57c24b20e82b8be378fa1bf907b104e8c2b0f62c8e646a033408d00d7fc0ac952a814166bb86508b843c06f10fa4d9f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200139);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_cve_id("CVE-2024-21609");
  script_xref(name:"JSA", value:"JSA75750");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75750)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75750
advisory.

  - A denial of service (DoS) vulnerability exists in IKE daemon due to a memory leak when a IPsec SA rekey
    occurs. An authenticated, adjacent attacker can exploit this issue, via specific values for the IPsec
    parameters, to cause the IKE daemon process to stop responding. (CVE-2024-21609)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-04-Security-Bulletin-Junos-OS-MX-Series-with-SPC3-and-SRX-Series-If-specific-IPsec-parameters-are-negotiated-iked-will-crash-due-to-a-memory-leak-CVE-2024-21609
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07943e2d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75750");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/06");

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
if (model !~ "^(MX|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S9', 'model':'^(MX|SRX)'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S7', 'model':'^(MX|SRX)'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'model':'^(MX|SRX)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4', 'model':'^(MX|SRX)'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3', 'model':'^(MX|SRX)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2', 'model':'^(MX|SRX)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3', 'model':'^(MX|SRX)'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3', 'model':'^(MX|SRX)'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R1-S2', 'model':'^(MX|SRX)', 'fixed_display':'23.2R1-S2, 23.2R2'}
];

var override = TRUE;
var cmd1 = junos_command_kb_item(cmd:'show configuration | display set');
var cmd2 = junos_command_kb_item(cmd:'show system processes extensive');
if (!empty_or_null(cmd1) && !empty_or_null(cmd2))
{
  override = FALSE;
  if (!preg(string:cmd1, pattern:"^set security ike gateway ike-policy", multiline:TRUE) ||
      !preg(string:cmd1, pattern:"^security ipsec vpn ike gateway", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');

  if (!preg(string:tolower(cmd2), pattern:"iked", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'running the iked process');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

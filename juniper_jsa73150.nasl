#TRUSTED 8296b8634f5bdcad2be48ee3a7d32b84529f3f0f6935374658c1b747a19a35135165f76cd93681140ddb736fe6f7a61775326b6785c57e45a18023ae309ab6c0d9693fed045007e6ebd5320e62b0e23a48d0b7e8c1e6b6dd583f111c86520564f38f771eb76990f90b72ca2668939585b55c6cad253760addc741aa77292925fff7a346bd8d4dc8ae4c897daf1e86f970f24fa21f1ddde15f1fe63a8c05c3de8a122eba7e04a060bbffe03259e28825aa1dae42e5e85118e42ca0535050b7dcaf9c8fd8563733a0131cb31fb7ebbffc0147288eafbae016e5e66a4b35986e1d1f9e1f7f0c399cae432fd950e3c05550434799b2080ae56fe4f475e5034e512d517529c93c2fba968d49bcf65d75cadd4116c4ea30e8764bb9f46cbc9e6b371658df6309b4a1e2b57d68dbb167b2464085ee7ae6fff78e80caaaa7be0bbe63cc1d2d5af6b2aa9034c95646a16bcc62434ee851f84a73b1f93419ce11441d7ef2bd92f8536ea8201accd24b19176455a317326ae75fd4b0a833ae6dc1ed90720362b3be57a5e5c65409c036a42c462235767018f4dd30011daeef30f4f12075458b866c48b1634829fe233ebe5fd0eb260b15262f865c6b177fc688dfeec18c60feeb838dc3dd40c825f0a8ea9f3c6f1f0f5ff2bdb4a474d697b6482ccdc87edc06fe61ae661bda8b826a798e8a75e224b39209e0d9bc12616caaf4b3575c0546a
#TRUST-RSA-SHA256 abcc13b6cd7f6a992a65b2190ab37bcaabbd55fff1487847891bebffae92aec481b525c84f9de2c22d827f3446d19ced7167720438f0f698f97fb50e100065463b9fbabcae308e5148d4abcafd83180e081610fdb884af088b24d9710babb4e89e125523b9dabc8421428e622539a6f2d0ef6551e56e53e080f8245bc51e7e8bac3257a8557bc9da6c15b98e3260953e0694d146eae1908822b728a05de41ffc086a9ace51bda25256325d02455c4fcf87fce2a9d2e6e8d78c9da27f22f31f6f0404f6f10903e7971605c8b594d86f2de0b64e026e71453314aa3e6bc704c89084d1a81c184899fdb82d8233c5cfc66e92d3f9b3c522304cc095c5a9a6af902533bbb92960e072c8df8e10aff94718b5d92bdb1a486cadbda158895f5cde5335b90319f5135027c087ab902c812a3df829833fc9ec14ff398c8ce8fad995b9a4c5415b2433f009b5a2307a207056320e803e3483c494212d806726d36c1ffa13a75a3131982bdb44b495e29833cc08afe0e97f47d0eaba51535588e6cfb832133508abe77d2cdef414560712f218b1e66e660db733637665db0978cf288591e237516ba1e3b72001eb71c3424cdece9747f8e8f2eb1735ef4637d94af8b4c3beae9939583833e028c9bc2d706c00a6e5ae2ac869a39d78e5df47a465574651dbbdcf01bccbe0287b78f2abec8ba23ed2cce320b9f7bd8af014d62d2d1be12543
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183504);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2023-44186");
  script_xref(name:"JSA", value:"JSA73150");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73150)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73150
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in AS PATH processing of Juniper Networks
    Junos OS and Junos OS Evolved allows an attacker to send a BGP update message with an AS PATH containing a
    large number of 4-byte ASes, leading to a Denial of Service (DoS). Continued receipt and processing of
    these BGP updates will create a sustained Denial of Service (DoS) condition. This issue is hit when the
    router has Non-Stop Routing (NSR) enabled, has a non-4-byte-AS capable BGP neighbor, receives a BGP update
    message with a prefix that includes a long AS PATH containing large number of 4-byte ASes, and has to
    advertise the prefix towards the non-4-byte-AS capable BGP neighbor. (CVE-2023-44186)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73150");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73150");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S8'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S8-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R1-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S6'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S6-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S5-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S5-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S4-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S2-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R2-S2-EVO'},
  {'min_ver':'22.3R3', 'fixed_ver':'22.3R3-S1'},
  {'min_ver':'22.3R3-EVO', 'fixed_ver':'22.3R3-S1-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1', 'fixed_display':'22.4R2-S1, 22.4R3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-S1-EVO'},
  {'min_ver':'22.4R3-EVO', 'fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set chassis redundancy graceful-switchover", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the Graceful Routing Engine Switchover (GRES) feature is not enabled');
  if (!preg(string:buf, pattern:"^set routing-options nonstop-routing", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the Nonstop Active Routing (NSR) feature is not enabled');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

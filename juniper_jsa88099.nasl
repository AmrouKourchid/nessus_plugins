#TRUSTED a9cf607d177da30af46fc3c424a460e4166f326c60095cdb33b91da11a86c4164a9592f9c3312d6456924a4279ae35b06365bb2d7d8a217104ef776574e8aa03a4ec77e92182ac56e753bb4fcab726cadde8a7386b52493b7c7a89bf593e26fc95bed729683b9e2354e9eb12cf70691c6e562b242f048b4ab6027af0438dfa667bd556605fb8d4158b280b6fa36e5a84d7a6427cb2611b06c2fd659e10ffadcd6b9dac31d71778e0822a4c9e06dad379a09b74d83fb1f6c149718bb09f3943df29f65a412a25c92e3c7c88f7e801a99ff7f38bc9be78dca8f1654d4527d50ccda9e0825e588dfe3a5804ebe3102384b36921d4924bef4d34606842bd2e71cc77f55e8291f136113641f9142d9e1a5862f445388e6d0b002c76e3a03ec8c4afa89806f7969d002f57cef9d7467b07eaa81681af429c5c4fc39c99d3bb4657d580b9312418c7a82920d5eab18c1b445e9c15c75bb789b7913c0ce64de6b7993aa0b333045d88598dbd982f6180439a90dc7c0c3dcca483a9d52fd09ca799db71da12ebbaaa897a01425310954287db1211fd88d92e7678c62caf6f0a418bde1dd0f6ffb2d4927e120b12ac38d3e383028ce07e0fd7af10ff81b640c9a36f7bb0303511aa0e9cd661b2df3c7fac5a29e7dc8b500a57f1298fc48e1e0967017724b0080e5dea76f8cc90ba813c74d72501ce0c67a7ea8b44882051bf03894a76d0a9
#TRUST-RSA-SHA256 3ea59d677d2a9c2ea60922c45c6b044f8370028c995e5a438bfba8757e414b4b518e1ce5adbb4e2a945c9a26afef988e337e347876067cc087d91039a0a520d7d38bc3b98b49bc711e47c53a7a188bbcc85c5b23fcd523d2de353c5db3dd70b82d8d5ce1836183915e633ab7123891f21b7bcc1e5dc13c916fcceb4aaf8381e61fee04ffa5d960554bf5dbbe1863eaf538735f74bcd9c0a1af85573c97c34a52f8ca98f5eaf0a32aa51509b47bfd5d32a2abe0a298509123f64fa2988f7bdc9b2f8994a26baeaff292d78a79435ab93357d46a5709d5a77ed01fa4a25a2cd7214b112f7c1f2539979157858dd759d511424ffd9fe70d2dfbb13a6db62aea0d739b57aefb2537a7f17c3111adf83750ec4e8d129d7cae361dccc152591c8744aa466850ec7b19764453b956b9cec8706d26f60645755fd099c90cc09fe573b6f252c680a1626e6c1985efc254a61074383a546f55f7126431dec6b65482325f4857d3fe06c0e29f7836f18f85660645a6c16fd3e087f62e2d63eda12af39571932331705aa532e23cb571e5aae8b75ff84b70e76244c59d6b23b39790c3185ca42241e61fb37e69d9de6b6d831f7e92eb64e7c85a62e509b61554272b768421a61df6c7d862df64e8231f237cdc79506c31dc5aa405c2f9a332b2f2e8e302082da9747f96bd9731c0bcdd768546383cf34c96e847feaa5ac8d4c9f4e89d3bd5c5
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211813);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id("CVE-2024-39515");
  script_xref(name:"JSA", value:"JSA88099");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88099
advisory.

  - An Improper Validation of Consistency within Input vulnerability in the routing protocol daemon (rpd) of
    Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated network-based attacker sending a
    specifically malformed BGP packet to cause rpd to crash and restart, resulting in a Denial of Service
    (DoS). Continued receipt and processing of this packet will create a sustained Denial of Service (DoS)
    condition. (CVE-2024-39515)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-With-BGP-traceoptions-enabled-receipt-of-specially-crafted-BGP-update-causes-RPD-crash-CVE-2024-39515
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01660f35");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88099");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.4R3-S8'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S8-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S5'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S5-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S4'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S4-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-S3-EVO'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-S2'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R2-S2-EVO'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R2'},
  {'min_ver':'23.4-EVO', 'fixed_ver':'23.4R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set protocols bgp group.*neighbor", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

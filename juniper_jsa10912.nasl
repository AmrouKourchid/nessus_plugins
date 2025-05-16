#TRUSTED 9582e0c9cc0546ecf1cc63eacc5baa3c7cc57d9ae4404a38af9076ada43d54861b534ecd32ba74bbeb0f9d1362d2cca3b0f602e35a9bc2775a44e4c4b7bc54e2ca79523014f3b94a43b3785ef10595a97d59ea94417cda7bd7af3ecf6a56c649d381b6b833284e0f591eef168504374752490299a4f57a401a2ed06feab4935c5141b8a533074a024a61b2efd9f0505b8871ea5d2246a3a1fea860e7b5019b0e1fb22ca8dd9a4930c68213f38554d7185ec8fb08ef585d067bffcbe24b8e26c90affcf76d2741cc41098c58f4a3354a0c5f677d902f09a2573368e39494cabe7bd67e5eeb5adac839a4480b10b6eb67f46f4c23c625ca9388a803b10659f0843dfd3c4ff4f1e5c8470273cf54cbadc719ef932ef159eec933862c0f926e283889944046f506f0e7c3c4b135ba1fd9c67deae4371ab92c619e651eb3c97d7d73e85e791766400063c2fe60cc251549305b8d40cc68fd4dda944ac5e2fc1e91548984f457efe323084108638223974bdfae9e65154fb8d6e2cfe8d8a0bfde2e9072935c93e81a1922c82b5df69b0ea4acb9bd05d6e1b04ecceeb4a0298a01d9cb6a6aab0ded133d8a46e44256c20020eea8117825f5a327f3052af14fdd40aa22c6c0a955f73caf44fe4c0df5503603b1b66711f6d91baaf5b3c8f79a971f182806f703811ed2e12855e115ca1347965f463d13cf07cb52f138b2e79ef506a7cc2
#TRUST-RSA-SHA256 5bdd691a9fc224e5a2631cb7731e7c604787291194ab9aa34c4bcbe0b23a8c070a8b0ed6a92985086d0295837c6618e26660b93362fafda07a8673272387ccb724fd91d08feafa1370e14b0972213f298516cf7fe7301d6aead7716a3a0578811996376530f6f46286126b70302284458b503036216e4aa95b72941f949fd2ce267e137e620f89a4a869f4c91f1277859038d7a268e0ab8284fa7a355e8ca4423a83471dd89c541f55ec5d34af1ef0b3be03c9818841888be2afe14cef302eaa493a3bf8ddc798a4f85e99aeed9e97b65699c4d5fb063ac5908cbfbd07be19ac6391973eeb2ae0c434c257edab0e2f0ce9e231047351d57628e3000f489108d614bb49dc3a99a0abad15b172131d73f5ec4723e3968ef2d685c6daf5575c958f5b8e0ec8fc12ceafd2e719da229fa7e374aa515e2d833b8298f75facb9cd5dd70ca3359a137551e99982660fc5fac86164e3278163a6cb121b13b07b451c92914bbfb1b15922168b9eaa892ce36e113c1a1f2e9d4fb9581869ad1c7d9a5372cb1b0b900db55596134f2d82d8a66a261cd8974dbd95ce0d6b180ffc3dcedb5c2fbb3765b875f4d9c6ddfad987476d25925d5d0a452b7f65c13bfc61fc15b4072b490de51f16e53f77c22323b3ba83cb68b56f8a9dd42bbf62b2b097c12e7a5c6494b753061fc13cb259f8f9b5deb028b41c6418c7412a0fa094c3765b2d0caff9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121111);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/27");

  script_cve_id("CVE-2019-0012");
  script_xref(name:"JSA", value:"JSA10912");

  script_name(english:"Junos OS: pd crash on VPLS PE upon receipt of specific BGP message (JSA10912)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability which
allows an attacker to craft a specific BGP message to cause the 
routing protocol daemon (rpd) process to crash and restart. While rpd
restarts after a crash, repeated crashes can result in an extended 
DoS condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10912");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10912.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.1X46',   'fixed_ver':'12.1X46-D81'},
  {'min_ver':'12.3',   'fixed_ver':'12.3R12-S12'},
  {'min_ver':'12.3X48',   'fixed_ver':'12.3X48-D76'},
  {'min_ver':'14.1X53',   'fixed_ver':'14.1X53-D48'},
  {'min_ver':'15.1F',   'fixed_ver':'15.1F6-S12'},
  {'min_ver':'15.1R',   'fixed_ver':'15.1R7-S2'},
  {'min_ver':'15.1X49',   'fixed_ver':'15.1X49-D150'},
  {'min_ver':'15.1X53',   'fixed_ver':'15.1X53-D68'},
  {'min_ver':'16.1',   'fixed_ver':'16.1R3-S10'},
  {'min_ver':'16.2',   'fixed_ver':'16.2R2-S7'},
  {'min_ver':'17.1',   'fixed_ver':'17.1R2-S9'},
  {'min_ver':'17.2',   'fixed_ver':'17.2R1-S7'},
  {'min_ver':'17.3',   'fixed_ver':'17.3R3-S2'},
  {'min_ver':'17.4',   'fixed_ver':'17.4R1-S5'},
  {'min_ver':'18.1',   'fixed_ver':'18.1R2-S3'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
  {
    override = FALSE;
    var pattern = "^\s*set protocols bgp group .* family l2vpn auto-discovery-only";

    if (!junos_check_config(buf:buf, pattern:pattern))
      audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
  }

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);

if (!isnull(fix))
{
  junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
}

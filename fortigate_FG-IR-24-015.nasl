#TRUSTED 9dd44f504e8d17e9e69a161cfa3e9f46d0c81a23053c74927fd5af6542c4785f7f62613140b70afb6fa760531e826d72c6765571f41feb6897bc30f97052922c2e2c5938dd0e5d9d938dbb3f5c1bd3e86a4c1abf9a56f16bb7f45315fb9f2910a2d98044be0739f5b3e7180dc69442dc6f10fb747b2b98b9b3a7ba1edd6d5541ef35c1f3150a048e8ce5490a98a8a95bdc6026471c346828b21f53ac98c67e3e43a70c9994e59608b6a1f1398072757aabeecd78e0bd6b804c372a550a2b573aa30632c4ddf2aac9556e5b8ac1e29d6e11b76f62503e97177f7e6cf3951938c420f38d519411c0c5258622319ccca92c869fdb1decc050a38f9b4d2eab0eb7261475a536d3908e25972841f1dd40c5224983aee282a34f175ecce7cad88fd53c266899d23f960b05255ecbb2411771b300ecd1dd947f9909aeeaba6c7d20bc27306f55209968504c60f15c5c8a6318badd9eab6c76b8215ba78cea558a3fcc3ec2d8b7a3239fa4531ec057ddec32833cd5e241d2eb69869a2dce8117f58327f8700b4a2fcbbabf1c0f11e182b06a7824617986b11fddbcd493ead8afa5c0d83c3623d2a46702d30e8109f1b52f56283e4afcb0a5c899ceedf4e72e33b68dccee86e6a67e034802f8c0d36def6b5edf326b8c20b5357ac977ecdc10df56a27921b032ddcfabd2990fb8c82589b7b87ef6a8d67ad358cfdacc15742cd528869a6d
#TRUST-RSA-SHA256 48fda7ed63767701301f7aad5c3d6ceeb7513026dbbd96611f72258dd9114c3136caf17d4ae726615a0cd2ab60128ff8061e919869646e9cc272a0d194294f41632a6327ed2bee984558c14a97379bcbcb5438b70450469e3fd0c9839e9623cb518b94c58ddc8fbfa281d716e2f0f8f2411cd7a4720a7424ff90a34186de0939a4158eac18156574ac55b44047137fab27f15e1884731993a098d3e6f3398ee97a6b717767d32bbb8f5ad76c93910279754ef967fee69805a4cca0c5a65a0472784b930c72fdd349a59ba6b18452c6dd3bb67b7bebbbadf18e4be18c55c3f8075b05b70792b1e6bbd98a0245d73cfb4e483336881e5aad4f23e90428a3dd91526db822f9bcdcc682411c1fffef6d40b9380e8b7e338312c8cbefdb0ee1bb262ff61d11433ba7513a40450cd5eef62e68caf23203f756d88004915fcfd0347e549d4c5c6fd389522bf520bfbf6b021e42cb5b064d575cfadefd62f8f6940cfbdea8a12d0c295a6d0b8231d27e69aa0770c43e0c6b3d0a09090bd40698fb7038694afe25d1dcb0a500ea75eda5ea82652f4aba06b8c160aa25be699b36039947d6a1ba4ecdddc6c6ae5fcb3d1e759015c707927832bc17610428fcfe6ceac9327a1b642053def733060fb6706b153d2f605e3926f3340740acaba7ca8160a3315047740bf76f3c36b268d12c265f5117f4a746d61ea305a0b3876b2c30ce818893
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190238);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2024-21762");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/16");
  script_xref(name:"IAVA", value:"2024-A-0079-S");

  script_name(english:"Fortinet Fortigate Out-of-bound Write in sslvpnd (FG-IR-24-015)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-24-015 advisory.

  - A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through
    7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0
    through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13,
    1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via
    specifically crafted requests (CVE-2024-21762)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-24-015");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate version 6.0.18 / 6.2.16 / 6.4.15 / 7.0.14 / 7.2.7 / 7.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21762");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_fortios.inc');

# Since there's a workaround specified in the advisory, we're making this require paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.0.0', 'max_version' : '6.0.17', 'fixed_version' : '6.0.18' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.15', 'fixed_version' : '6.2.16' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.14', 'fixed_version' : '6.4.15' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.13', 'fixed_version' : '7.0.14' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.6', 'fixed_version' : '7.2.7' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.2', 'fixed_version' : '7.4.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

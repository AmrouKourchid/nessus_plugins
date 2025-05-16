#TRUSTED 8c665d53697b4f60ab3f0f6e9660c369077a47153ff2e4ce4aae5b47d3d81f3573db8b3e582a15e0ba03a984087b4a373596b555fb4d91bd0b2c288e687af866772fa11b561b8d9164ec4fbf24966aea11888163556cca6553f62d66ca3c4f0968c608c3dae8d8f0d77987949577df5a5f502ab02daa867655cb893b3b17678bd25bd33208559df040f0bd03f1e28c61934f618b782786503fe8d2cde394100d92a1059b321ce98b27b517866096fd8c725b1e39f4165252bb940931e4c1575f4120815ab3af51139fe4dcd0e5b944ffc0ac0a659c860e19bde578446d2576ad53c72c0538d7eebc3f42a30e300240e80770939345e6c166bb7ee8cde7acf743d57729ca9a825d3bf0155035013402aca8677cf23da413152d5c2626fe727aaba521a4350fced72a69a205fb5290e31a96dc8e995650c3a0a2fb149c18b059e3374daa7d7f2c99508ab26add32e479643ad7d643e2d173ee85ea129e40aaa402960fe2baf9b1ee0a7f8b39e488c131db41de68b2bd4ece8c2528653a2a211590ac847ac9c9a56ce7c0c714e1937535fb2adeca67660bfe3e68857374a7d2b9df3dd1442268698f11f788d103e7d43d05e456782488712fb81c3ec3e0a5c98c72f3028be947c9f158455aa2138f6cad3b9762ec9a0deec2cbf108a1e36a9d414c81652ba770b7cf2f8b8a57258f41d576bd9e6c420e63d8aa511dc1d19c1cac5c
#TRUST-RSA-SHA256 90fa393ca6cf82d15bfa3a26f2a3e8285ddbe811f55872a2454bee6b828c6a3ec5ddeffbb22ab86aecf56ee3e6fe8cd0e504620164653f6fac693a2cdf8fe19c3427505a5fc0244c2255d52dba6e68d80ddee5f251f878f6fd897d5d47d79625b9dfbbba52042487330844a30f5eb2eaf0ef496cc3c55e277789f6db23b4ea5a24a46562a7a87f0e9b21ab3b6636a9f6b3690cde823d1405197b6e32df1537de21f5354cac29d979349fc44c1b7dc0dd698447678abffce3a3b0dddc318949732c4f567ff840b7fef22337483cd00b361425cde38a1a5d59f57b6c97beaa4a4396e6df3edcea8a3e066b71d860e98bac01c9ae8fc4c4438b5302a5b5c98cf4291084ffbff77ecd6bdc68cc44ea4fcffbf4e4048b5b345ed146ccd997b8cfa3378b84d4d8bd787a80364599007d91c0930a76dc1d1b598a93641618da7688055f87013d0c989480ba1de958a43b1ba1bcfea32347908abfd19dcf9c9774de81bd7362bfcc9250ed13755279cf463c27474f9b329fcc7984cf0b368d11f4512aeb217ca4e45508fc26eccdee11ca3b2b64315f90c6c1f4f8b70501f31e51ffac0f92b761c52c51b0ac235c21977ccae98fd45e48aec5cc1f60b952929d31e70184861994b29604e10cf64bc726e6f0c8c4a9d37531995429be7131ec3123ee0d44b15604539c96382c541c3d41e03759cdc1f4d691eb7059fc492cb623adb45e42
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144983);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2021-0221");
  script_xref(name:"JSA", value:"JSA11111");

  script_name(english:"Juniper Junos OS DoS (JSA11111)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11111 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://supportportal.juniper.net/s/article/2021-01-Security-Bulletin-Junos-OS-QFX10K-Series-Traffic-loop-Denial-of-Service-DoS-upon-receipt-of-specific-IP-multicast-traffic-CVE-2021-0221
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1c0e11e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11111");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^QFX1")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S12', 'model':'^QFX1'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S3', 'model':'^QFX1'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S11', 'model':'^QFX1'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S6', 'model':'^QFX1'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4', 'model':'^QFX1'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S5', 'model':'^QFX1'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S5', 'model':'^QFX1'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6', 'model':'^QFX1', 'fixed_display':'19.1R1-S6, 19.1R2-S2'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R3-S3', 'model':'^QFX1'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5', 'model':'^QFX1'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S1', 'model':'^QFX1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S5', 'model':'^QFX1', 'fixed_display':'19.3R2-S5, 19.3R3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S2', 'model':'^QFX1', 'fixed_display':'19.4R2-S2, 19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2', 'model':'^QFX1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S2', 'model':'^QFX1', 'fixed_display':'20.2R1-S2, 20.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);

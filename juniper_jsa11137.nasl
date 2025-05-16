#TRUSTED 212a9faaeafe920d4d2f52548eaf2d2abc72b25f5e8fe5710e7c8128f4ef75762c31adb1a35cad7a0b7017ecc95540f9bc681712e89b1bfe5533448bbdaad5733c1169764a569f413577e9d42bed15dd00854624ad064807790ab5d9f57e9c41a90c07650beab70c7167817a31fa4ddf3dafda4cae8314b9b02d91b027082c812af9442e120b4f9ce2042c8f5004774ef5218c76a8a46c6df6bd10484ac2cc29d20aa826a95ebe387897263a2e5fa465300e9a9ac53561c9e38beee206f4ec9b89ef3c414f0e11518b7370a58f3eb0bf70c47585888c08dfd327bf1d1d6914864557a3dfe88bcb62c1ca2446ef9b07484602445d9725013e046fe08a4f5bd01e5a2ce038067fdeb9b7ccee7cab23b0b8f2796bcfb91af7f5d1783d0050d6ac817ac2b77b753576f44b2f382c6da8ae8e41c863676437015550d758706795a5b7c029bc14c924cc0d0e4c47f112570ef09b94f76af668955501ae7c7b9171fcdad84995639bdf18b068208ef7f6daacca9ef13b48df20d509e5a76dcb177e79e6310d2c3583583ae9ed1aaf22ddb4b98386d0d2c653abf2012534df2bd926f3955b5f0e80935ace7c1d1334728bc3385fe129695840b7f523eb62436a2b5749977f1466c74c49ee54aa3123ac1c650f397666d552523064441fa68bb42b5791cb6d186d0eace6cee811bf0e10adeda978d81698c670ba3fdf6393639023429a5f
#TRUST-RSA-SHA256 76ddaff1407bc180cece8a01cc2491a9260fc62212bea770711671f56585af9b0d83944f7bf552a2527562ed32c4136c698e1c8149fd222b6982a62c17e6e8b87eda9aa5ef3f9ec0f64912209d3a892c0c8ef4a8d5b4fb7f7350c10945e58e964dc1b941a1f8ac615a7d00ee65d752b3b34e3cd4bb6ee45b2be715bc9eced699d39b12661594bc08e7e9a7c45b2d4ff2e46cad1e2eecb4daeb081d3e4b2e3f7bd96cf87848fa2e7cc3458eab7bdaa72bd6eaa6df9bb568de2bf2af96c4f5cc2f30feb00beb95346e7019b0138bfefbe12ecf8145069b5c62c3a4fb2038998ad21cc95da1b4c7988bd92317202ade410febb7bcc6cb0bd3a8aa630d1e43f023feb140d6bbb6f9bd4e71fbb1296deacce6b43a1428fc110268e53e8feea371012fa0788ce9d264bd92ab962e6bf18016380de8bd9f84c0146df8a79d9a06850fa29a7b60e7e51c6fe198b8cf1d2cd7c91c2b7f18723041fe8a597538557f5eef2c8365f644f33785075fcb2f636b645f4e64b78398efe434dec2f48a81cba5ed51f4d7512843a155695733170396c1ff45d242d444aea007dc32b315561e1a396f0f490153de338bf70fcea8a94fc181492f2ad96563633e31607c93504730b3fc2b94abf23e7103e38e7ec426ba3e28d45268a8dda349a4f34d891e0a7e5e003ae2918f316858fa7ad4dc91016afa9f5ea58eb2f4302dc5f3e35d05437d3a5549
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149369);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/24");

  script_cve_id("CVE-2021-0244");
  script_xref(name:"JSA", value:"JSA11137");

  script_name(english:"Juniper Junos OS DoS (JSA11137)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in
the JSA11137 advisory. An unauthenicated remote attacker can bypass the storm-control feature on devices due to a rare race
condition exists in the Layer 2 Address Learning Daemon (L2ALD) of Juniper Networks to cause denial of service (DoS).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://supportportal.juniper.net/s/article/2021-04-Security-Bulletin-Junos-OS-A-race-condition-in-the-storm-control-profile-may-allow-an-attacker-to-cause-a-Denial-of-Service-condition-CVE-2021-0244
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?524bbba5");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11137");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

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


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D49', 'model':'^EX'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S6'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D191', 'model':'^SRX', 'fixed_display':'15.1X49-D191, 15.1X49-D200'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R7-S7'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S11', 'fixed_display':'16.2R2-S11, 16.2R3'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S11', 'fixed_display':'17.1R2-S11, 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R2-S8'},
  {'min_ver':'17.2R3', 'fixed_ver':'17.2R3-S3'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S5'},
  {'min_ver':'17.3R3', 'fixed_ver':'17.3R3-S7'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S9', 'fixed_display':'17.4R2-S9, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S5'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S6', 'fixed_display':'18.2R2-S6, 18.2R3'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S7', 'fixed_display':'18.3R1-S7, 18.3R2-S3, 18.3R3'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S5', 'fixed_display':'18.4R1-S5, 18.4R2'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S4', 'fixed_display':'19.1R1-S4, 19.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);

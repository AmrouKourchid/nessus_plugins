#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178191);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2017-7653", "CVE-2017-7654", "CVE-2017-7655");
  script_xref(name:"JSA", value:"JSA71655");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA71655)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA71655 advisory.

  - The Eclipse Mosquitto broker up to version 1.4.15 does not reject strings that are not valid UTF-8. A
    malicious client could cause other clients that do reject invalid UTF-8 strings to disconnect themselves
    from the broker by sending a topic string which is not valid UTF-8, and so cause a denial of service for
    the clients. (CVE-2017-7653)

  - In Eclipse Mosquitto 1.4.15 and earlier, a Memory Leak vulnerability was found within the Mosquitto
    Broker. Unauthenticated clients can send crafted CONNECT packets which could cause a denial of service in
    the Mosquitto Broker. (CVE-2017-7654)

  - In Eclipse Mosquitto version from 1.0 to 1.4.15, a Null Dereference vulnerability was found in the
    Mosquitto library which could lead to crashes for those applications using the library. (CVE-2017-7655)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Multiple-vulnerabilities-have-been-resolved-in-MQTT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5e55cff");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA71655");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'19.1R3-S10'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S7-EVO'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S7'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S8'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S11'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S7'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S6'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S7'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R1-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S5'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R1-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S4'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R1-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S4-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);

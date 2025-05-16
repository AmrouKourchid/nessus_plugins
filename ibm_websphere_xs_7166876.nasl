#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206334);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/10");

  script_cve_id(
    "CVE-2023-38264",
    "CVE-2024-3933",
    "CVE-2024-21011",
    "CVE-2024-21085",
    "CVE-2024-21094"
  );

  script_name(english:"IBM WebSphere eXtreme Scale 8.6.1.0 < 8.6.1.6 (7166876)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere eXtreme Scale installed on the remote host is prior to 8.6.1.6. It is, therefore, affected
by multiple vulnerabilities as referenced in the 7166876 advisory.

  - In Eclipse OpenJ9 release versions prior to 0.44.0 and after 0.13.0, when running with JVM option
    -Xgc:concurrentScavenge, the sequence generated for System.arrayCopy on the IBM Z platform with hardware
    and software support for guarded storage [1], could allow access to a buffer with an incorrect length
    value when executing an arraycopy sequence while the Concurrent Scavenge Garbage Collection cycle is
    active and the source and destination memory regions for arraycopy overlap. This allows read and write to
    addresses beyond the end of the array range. (CVE-2024-3933)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u401,
    8u401-perf, 11.0.22, 17.0.10, 21.0.2, 22; Oracle GraalVM for JDK: 17.0.10, 21.0.2, 22; Oracle GraalVM
    Enterprise Edition: 20.3.13 and 21.3.9. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise
    Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. (CVE-2024-21094)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Concurrency). Supported versions that are affected are Oracle Java SE: 8u401, 8u401-perf,
    11.0.22; Oracle GraalVM Enterprise Edition: 20.3.13 and 21.3.9. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web
    service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security.
    (CVE-2024-21085)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7166876");
  script_set_attribute(attribute:"solution", value:
"Please see vendor advisory for details.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_extreme_scale");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_websphere_extreme_scale_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere eXtreme Scale", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'IBM WebSphere eXtreme Scale');

if (app_info['version'] =~ "^8\.6\.1" && report_paranoia < 2)
    audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '8.6.1.0', 'fixed_version' : '8.6.1.6', 'missing_patch' : 'PH62624', 'fixed_display' : 'Please see vendor advisory for details.' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

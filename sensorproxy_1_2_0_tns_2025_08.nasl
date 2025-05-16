#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235604);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2019-16276", "CVE-2024-9143", "CVE-2024-13176");

script_name(english:"Tenable Sensor Proxy < 1.2.0 Multiple Vulnerabilities (TNS-2025-08)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Sensor Proxy installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Sensor Proxy running on the remote host is less than 1.2.0. It is, 
therefore, affected by multiple vulnerabilities as referenced in the TNS-2025-08 advisory.

  - Go before 1.12.10 and 1.13.x before 1.13.1 allow HTTP Request Smuggling. (CVE-2019-16276)

  - Out of bound memory writes can lead to an application crash or even a possibility of a remote code 
    execution, however, in all the protocols involving Elliptic Curve Cryptography that we're aware of, 
    either only 'named curves' are supported, or, if explicit curve parameters are supported, they specify 
    an X9.62 encoding of binary (GF(2^m)) curves that can't represent problematic input values. Thus the 
    likelihood of existence of a vulnerable application is low. In particular, the X9.62 encoding is used for 
    ECC keys in X.509 certificates, so problematic inputs cannot occur in the context of processing X.509 
    certificates. Any problematic use-cases would have to be using an 'exotic' curve encoding. The affected 
    APIs include: EC_GROUP_new_curve_GF2m(), EC_GROUP_new_from_params(), and various supporting BN_GF2m_*() 
    functions. Applications working with 'exotic' explicit binary (GF(2^m)) curve parameters, that make it 
    possible to represent invalid field polynomials with a zero constant term, via the above or similar APIs, 
    may terminate abruptly as a result of reading or writing outside of array bounds. Remote code execution 
    cannot easily be ruled out. The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue. 
    (CVE-2024-9143)

  - A timing side-channel in ECDSA signature computations could allow recovering the private key by an 
    attacker. However, measuring the timing would require either local access to the signing application or a 
    very fast network connection with low latency. There is a timing signal of around 300 nanoseconds when 
    the top word of the inverted ECDSA nonce value is zero. This can happen with significant probability only 
    for some of the supported elliptic curves. In particular the NIST P-521 curve is affected. To be able to 
    measure this leak, the attacker process must either be located in the same physical computer or must have 
    a very fast network connection with low latency. For that reason the severity of this vulnerability is 
    Low. The FIPS modules in 3.4, 3.3, 3.2, 3.1 and 3.0 are affected by this issue. (CVE-2024-13176)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2025-08");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Sensor Proxy  or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16276");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:sensorproxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sensorproxy_installed.nbin");
  script_require_ports("installed_sw/Tenable Sensor Proxy");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Tenable Sensor Proxy');

var constraints = [
  { 'fixed_version' : '1.2.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

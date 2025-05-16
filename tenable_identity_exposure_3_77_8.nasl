#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215200);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/14");

  script_cve_id(
    "CVE-2024-11053",
    "CVE-2024-25629",
    "CVE-2025-0167",
    "CVE-2025-0665",
    "CVE-2025-0725",
    "CVE-2025-1091",
    "CVE-2025-0760",
    "CVE-2025-23083",
    "CVE-2025-23084",
    "CVE-2025-23085"
  );

  script_name(english:"Tenable Identity Exposure < 3.77.9 Multiple Vulnerabilities (TNS-2025-01)");

  script_set_attribute(attribute:"synopsis", value:
"An identity security and threat detection platform running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Tenable Identity Exposure running on the remote host is prior to 3.77.9. It is, therefore, affected by
multiple vulnerabilities according to advisory TNS-2025-01, including the following:

  - libcurl would wrongly close the same eventfd file descriptor twice when taking down a connection channel
    after having completed a threaded name resolve. (CVE-2025-0665)

  - With the aid of the diagnostics_channel utility, an event can be hooked into whenever a worker thread
    is created. This is not limited only to workers but also exposes internal workers, where an instance
    of them can be fetched, and its constructor can be grabbed and reinstated for malicious usage. This
    vulnerability affects Permission Model users (--permission) on Node.js v20, v22, and v23. (CVE-2025-23083)

  - When libcurl is asked to perform automatic gzip decompression of content-encoded HTTP responses with
    the CURLOPT_ACCEPT_ENCODING option, **using zlib 1.2.0.3 or older**, an attacker-controlled integer
    overflow would make libcurl perform a buffer overflow. (CVE-2025-0725)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2025-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Identity Exposure version 3.77.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0665");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-25629");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:tenable_ad");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:tenable_identity_exposure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ad_win_installed.nbin", "tenable_ad_web_detect.nbin");
  script_require_keys("installed_sw/Tenable.ad");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable.ad');

var constraints = [
  {'fixed_version': '3.77.9'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
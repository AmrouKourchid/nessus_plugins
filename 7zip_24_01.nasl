#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209231);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2023-52168", "CVE-2023-52169");

  script_name(english:"7-Zip < 24.01 Heap-based Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The 7-zip instance installed on the remote host is affected by a heap based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of 7-Zip installed on the remote Windows host is below 24.01. It is, therefore, affected by multiple
vulnerabilities:

  - The NtfsHandler.cpp NTFS handler in 7-Zip before 24.01 (for 7zz) contains a heap-based buffer overflow
    that allows an attacker to overwrite two bytes at multiple offsets beyond the allocated buffer size:
    buffer+512*i-2, for i=9, i=10, i=11, etc. (CVE-2023-52168)

  - The NtfsHandler.cpp NTFS handler in 7-Zip before 24.01 (for 7zz) contains an out-of-bounds read that
    allows an attacker to read beyond the intended buffer. The bytes read beyond the intended buffer are
    presented as a part of a filename listed in the file system image. This has security relevance in some
    known web-service use cases where untrusted users can upload files and have them extracted by a
    server-side 7-Zip process. (CVE-2023-52169)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2024/07/03/10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7-zip version 24.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52168");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("7zip_installed.nbin");
  script_require_keys("installed_sw/7-Zip", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'7-Zip', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '24.01' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

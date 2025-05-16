#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197830);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2021-30640");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.46");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.46. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.46_security-9 advisory.

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/c4df8d44a959a937d507d15e5b1ca35c3dbc41eb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cccadfc4");
  # https://github.com/apache/tomcat/commit/749f3cc192c68c34f2375509aea087be45fc4434
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4512076");
  # https://github.com/apache/tomcat/commit/c6b6e1015ae44c936971b6bf8bce70987935b92e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aae142a7");
  # https://github.com/apache/tomcat/commit/91ecdc61ce3420054c04114baaaf1c1e0cbd5d56
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?496ee7c6");
  # https://github.com/apache/tomcat/commit/e50067486cf86564175ca0cfdcbf7d209c6df862
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc773f1c");
  # https://github.com/apache/tomcat/commit/b5585a9e5d4fec020cc5ebadb82f899fae22bc43
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e7f15c3");
  # https://github.com/apache/tomcat/commit/329932012d3a9b95fde0b18618416e659ecffdc0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ec11b5e");
  # https://github.com/apache/tomcat/commit/3ce84512ed8783577d9945df28da5a033465b945
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bce99b1b");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=65224");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.46
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afd6b0c0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.46 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '9.0.0.M1', 'max_version' : '9.0.45', 'fixed_version' : '9.0.46' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

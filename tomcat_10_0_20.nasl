##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(159463);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_cve_id("CVE-2021-43980");
  script_xref(name:"IAVA", value:"2023-A-0534-S");

  script_name(english:"Apache Tomcat 10.0.0.M1 < 10.0.20 Spring4Shell (CVE-2022-22965) Mitigations");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 10.x prior to 10.0.20.

  - The simplified implementation of blocking reads and writes introduced in Tomcat 10 and back-ported to
    Tomcat 9.0.47 onwards exposed a long standing (but extremely hard to trigger) concurrency bug in Apache
    Tomcat 10.1.0 to 10.1.0-M12, 10.0.0-M1 to 10.0.18, 9.0.0-M1 to 9.0.60 and 8.5.0 to 8.5.77 that could cause
    client connections to share an Http11Processor instance resulting in responses, or part responses, to be
    received by the wrong client. (CVE-2021-43980)");
  # https://github.com/apache/tomcat/commit/17f177eeb7df5938f67ef9ea580411b120195f13
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6ecd284");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?953e1d4d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.0.20 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:10");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '10.0.20', min:'10.0.0.M1', severity:SECURITY_NOTE, granularity_regex: "^10(\.0)?$");

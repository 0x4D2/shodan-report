"""Static EOL (End-of-Life) lookup table for common server products.

Data based on official vendor lifecycle pages (correct as of 2026-03-31).

Each entry:
  product_id      : internal identifier
  display_name    : human-readable name used in report output
  shodan_products : lowercase substrings matched against Shodan product/version fields
  version_prefix  : version string prefix this entry applies to ("" = any version)
  support_end     : date active/mainstream support ended (None = still fully supported)
  support_model   : "official"         â€“ unambiguous, vendor-published EOL date
                    "mainstream_end"   â€“ only mainstream support ended; extended support
                                         may still apply (typically requires licensing/SA)
  note            : optional extra context shown in the report
"""

from datetime import date

# Days before support_end at which status changes to "near_eol"
NEAR_EOL_DAYS = 365

EOL_DB = [
    # â”€â”€ WINDOWS SERVER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "product_id": "windows_xp",
        "display_name": "Windows XP",
        "shodan_products": ["windows xp"],
        "version_prefix": "",
        "support_end": date(2014, 4, 8),
        "support_model": "official",
    },
    {
        "product_id": "windows_7",
        "display_name": "Windows 7",
        "shodan_products": ["windows 7"],
        "version_prefix": "",
        "support_end": date(2020, 1, 14),
        "support_model": "official",
    },
    {
        "product_id": "windows_server_2003",
        "display_name": "Windows Server 2003",
        "shodan_products": ["windows server 2003"],
        "version_prefix": "",
        "support_end": date(2015, 7, 14),
        "support_model": "official",
    },
    {
        "product_id": "windows_server_2008",
        "display_name": "Windows Server 2008 / 2008 R2",
        "shodan_products": ["windows server 2008"],
        "version_prefix": "",
        "support_end": date(2020, 1, 14),
        "support_model": "official",
    },
    {
        "product_id": "windows_server_2012",
        "display_name": "Windows Server 2012 / 2012 R2",
        "shodan_products": ["windows server 2012"],
        "version_prefix": "",
        "support_end": date(2023, 10, 10),
        "support_model": "official",
    },
    {
        "product_id": "windows_server_2016",
        "display_name": "Windows Server 2016",
        # RDP banners include the full OS string in the version field
        "shodan_products": ["windows server 2016", "build 14393", "version 1607"],
        "version_prefix": "",
        # Mainstream support ended 2022-10-11; Extended until 2027-01-12 requires SA
        "support_end": date(2022, 10, 11),
        "support_model": "mainstream_end",
        "note": "Mainstream-Support beendet; Extended bis 2027-01-12 nur mit Software Assurance",
    },
    {
        "product_id": "windows_server_2019",
        "display_name": "Windows Server 2019",
        "shodan_products": ["windows server 2019", "build 17763"],
        "version_prefix": "",
        "support_end": date(2024, 1, 9),
        "support_model": "mainstream_end",
        "note": "Mainstream-Support beendet; Extended bis 2029-01-09 nur mit Software Assurance",
    },
    {
        "product_id": "windows_server_2022",
        "display_name": "Windows Server 2022",
        "shodan_products": ["windows server 2022", "build 20348"],
        "version_prefix": "",
        "support_end": date(2026, 10, 14),
        "support_model": "mainstream_end",
        "note": "Mainstream-Support endet 2026-10-14",
    },

    # â”€â”€ APACHE HTTP SERVER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "product_id": "apache_httpd_1_3",
        "display_name": "Apache HTTP Server 1.3",
        "shodan_products": ["apache httpd", "apache http server"],
        "version_prefix": "1.3",
        "support_end": date(2010, 2, 3),
        "support_model": "official",
    },
    {
        "product_id": "apache_httpd_2_2",
        "display_name": "Apache HTTP Server 2.2",
        "shodan_products": ["apache httpd", "apache http server"],
        "version_prefix": "2.2",
        "support_end": date(2018, 1, 1),
        "support_model": "official",
    },

    # â”€â”€ PHP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "product_id": "php_5",
        "display_name": "PHP 5",
        "shodan_products": ["php"],
        "version_prefix": "5.",
        "support_end": date(2018, 12, 31),
        "support_model": "official",
    },
    {
        "product_id": "php_7_0",
        "display_name": "PHP 7.0",
        "shodan_products": ["php"],
        "version_prefix": "7.0",
        "support_end": date(2019, 1, 10),
        "support_model": "official",
    },
    {
        "product_id": "php_7_1",
        "display_name": "PHP 7.1",
        "shodan_products": ["php"],
        "version_prefix": "7.1",
        "support_end": date(2019, 12, 1),
        "support_model": "official",
    },
    {
        "product_id": "php_7_2",
        "display_name": "PHP 7.2",
        "shodan_products": ["php"],
        "version_prefix": "7.2",
        "support_end": date(2020, 11, 30),
        "support_model": "official",
    },
    {
        "product_id": "php_7_3",
        "display_name": "PHP 7.3",
        "shodan_products": ["php"],
        "version_prefix": "7.3",
        "support_end": date(2021, 12, 6),
        "support_model": "official",
    },
    {
        "product_id": "php_7_4",
        "display_name": "PHP 7.4",
        "shodan_products": ["php"],
        "version_prefix": "7.4",
        "support_end": date(2022, 11, 28),
        "support_model": "official",
    },
    {
        "product_id": "php_8_0",
        "display_name": "PHP 8.0",
        "shodan_products": ["php"],
        "version_prefix": "8.0",
        "support_end": date(2023, 11, 26),
        "support_model": "official",
    },
    {
        "product_id": "php_8_1",
        "display_name": "PHP 8.1",
        "shodan_products": ["php"],
        "version_prefix": "8.1",
        "support_end": date(2025, 12, 31),
        "support_model": "official",
    },

    # â”€â”€ MySQL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "product_id": "mysql_5_5",
        "display_name": "MySQL 5.5",
        "shodan_products": ["mysql"],
        "version_prefix": "5.5",
        "support_end": date(2018, 12, 31),
        "support_model": "official",
    },
    {
        "product_id": "mysql_5_6",
        "display_name": "MySQL 5.6",
        "shodan_products": ["mysql"],
        "version_prefix": "5.6",
        "support_end": date(2021, 2, 5),
        "support_model": "official",
    },
    {
        "product_id": "mysql_5_7",
        "display_name": "MySQL 5.7",
        "shodan_products": ["mysql"],
        "version_prefix": "5.7",
        "support_end": date(2023, 10, 31),
        "support_model": "official",
    },

    # â”€â”€ OpenSSL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "product_id": "openssl_1_0",
        "display_name": "OpenSSL 1.0",
        "shodan_products": ["openssl"],
        "version_prefix": "1.0",
        "support_end": date(2020, 1, 1),
        "support_model": "official",
    },
    {
        "product_id": "openssl_1_1_1",
        "display_name": "OpenSSL 1.1.1",
        "shodan_products": ["openssl"],
        "version_prefix": "1.1.1",
        "support_end": date(2023, 9, 11),
        "support_model": "official",
    },

    # â”€â”€ ProFTPD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "product_id": "proftpd_1_3_5",
        "display_name": "ProFTPD 1.3.5",
        "shodan_products": ["proftpd"],
        "version_prefix": "1.3.5",
        "support_end": date(2020, 1, 1),
        "support_model": "official",
    },

    # â”€â”€ Samba â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "product_id": "samba_3",
        "display_name": "Samba 3.x",
        "shodan_products": ["samba"],
        "version_prefix": "3.",
        "support_end": date(2017, 3, 7),
        "support_model": "official",
    },
    {
        "product_id": "samba_4_0",
        "display_name": "Samba 4.0 â€“ 4.10",
        "shodan_products": ["samba"],
        "version_prefix": "4.0",
        "support_end": date(2019, 9, 18),
        "support_model": "official",
    },
]

# SiempreCMS-SQLi-POC
The user-search-username and user-search-name parameters in user_search_ajax.php are not properly sanitized before being used in SQL queries. The source code applies htmlentities() which only prevents HTML injection but does not protect against SQL injection.me, $perPage, $offset) appears to directly interpolate user input into SQL queries.

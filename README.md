1. Scanning Jenis File:
   - Backup/Archive: .zip, .rar, .7z, .tar.gz, .sql, .sqlite, .bak, dll
   - Konfigurasi: .env, wp-config.php, config.php, .htaccess, .htpasswd
   - Credentials: id_rsa, id_dsa, credentials.json, secrets.json
   - Git: .git/config, .git/credentials, .gitignore
2. Path Scanning:
   - Admin paths (/admin, /wp-admin, /phpmyadmin, /cpanel)
   - Upload paths (/uploads, /files, /media)
   - API endpoints (/api, /graphql, /rest)
3. Teknik Scanning:
   - Multi-threaded (40 workers)
   - Random User-Agent
   - Fingerprinting untuk bedakan halaman real vs 404
   - Cek keyword sensitif di response body
4. Input/Output:
   - Mode single target atau mass scan dari file
   - Hasil disimpan ke folder .result
  
   - <img width="1029" height="524" alt="image (1)" src="https://github.com/user-attachments/assets/cd1fd5af-62e2-4ad4-b3cb-5056db8e0a5c" />

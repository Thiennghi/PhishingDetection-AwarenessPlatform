<?php
/**
 * ONE config file for everything (git-ignored, never share it).
 *
 * Every request tries, in order:
 *   1. "live"  - your live MySQL (InfinityFree etc.)  -> works when this runs ON that host
 *   2. "local" - XAMPP MySQL on this PC               -> fallback on your computer
 *   3. both fail -> JSON error "Database connection failed: ..."
 *
 * On XAMPP the live host is unreachable (hosts block outside connections), so it falls
 * through to local. Keep the live values as placeholders until you deploy.
 */
return [
    'env' => 'development',   // no admin secrets required; set them below to use admin.html

    'db' => [
        // 1) LIVE - copy from the host panel > MySQL Databases
        'live' => [
            // GGC cPanel (site uploaded to the same server as the database): host is localhost.
            // InfinityFree instead: use its "MySQL host name" (sqlXXX.infinityfree.com), if0_ name/user.
            'host' => 'localhost',
            'port' => 3306,
            'name' => 'tduongdo_cyberguard',
            'user' => 'tduongdo_app',              // cPanel > MySQL Databases > user added with ALL PRIVILEGES
            'pass' => 'Nghi13062003',
        ],
        // 2) LOCAL XAMPP
        'local' => [
            'host' => 'localhost',
            'port' => 3306,
            'name' => 'cyberguard_db',
            'user' => 'root',
            'pass' => '',
        ],
        'local_fallback'  => true,
        'connect_timeout' => 2,   // seconds per attempt
    ],

    // Admin login (admin.html) - unchanged behaviour. Paste your existing values, or set the
    // ADMIN_PASSWORD_HASH / ADMIN_SECRET_TOKEN environment variables instead.
    //   php -r "echo password_hash('change-me', PASSWORD_DEFAULT);"
    //   php -r "echo bin2hex(random_bytes(32));"
    // 'admin' => [
    //     'username'      => 'admin',
    //     'password_hash' => '',
    //     'secret_token'  => '',
    // ],
];

# Administrator setup

## Local first-time setup (recommended)

1. Start the project using a local PHP server such as XAMPP and open `admin.html` through `http://localhost/...` (do not open it as a `file://` page).
2. If no administrator credentials exist, the page displays **First-time administrator setup**. Choose a username and a unique password of at least 12 characters, then confirm it.
3. The setup creates `admin_secrets.php` with a PHP password hash and random API secret. The plain-text password is not saved. Setup is one-time and the web setup endpoint only accepts POST requests from localhost.
4. Sign in with the username and password you just created. The database must be reachable; admin login rate limiting uses MySQL.

## Remote hosting

For remote hosting, do not expose first-time setup publicly. Connect through SSH/CLI and run `php scripts/setup_admin.php`, then upload the generated `admin_secrets.php` privately alongside `config.php` using your hosting file manager or secure transfer. The script is CLI-only.

**Keep `admin_secrets.php` private and never commit/share it.** It contains a password hash and admin API secret. Database settings are not changed by setup. If login fails, confirm the file exists on the server and that MySQL is reachable. Five failed login attempts within 15 minutes can trigger temporary rate limiting. If an administrator forgets the username or password, run `php scripts/reset_admin.php` from a trusted terminal. Enter a replacement username and password when prompted. This replaces the credentials and rotates the API secret without deleting report data or changing database settings. It is CLI-only and requires filesystem/terminal access; there is intentionally no public “forgot password” link because there is no verified email recovery configured. The original `scripts/setup_admin.php` remains for initial creation when no credentials exist.


## Forgotten username or password

Use the recovery script from the project root:

```bash
php scripts/reset_admin.php
```

Choose a username and a unique password of at least 12 characters. The script prints the new username, but never prints the password. Sign in at `admin.html`. Run it only on your own computer or through a trusted SSH session. Do not upload or expose this script as a public web endpoint.


## Forgot username or password (browser button)

On a local XAMPP installation, open `admin.html` using `http://localhost/...` and click **Forgot username / password?** beside **Sign in**. Choose a replacement username and a unique password of at least 12 characters, confirm it, and click **Reset administrator account**. Then sign in with the new credentials. This rotates the API secret and leaves reports/database settings untouched. Browser recovery is localhost-only; it is not exposed to remote visitors.

On remote hosting, connect through SSH or a trusted terminal in the project root and run `php scripts/reset_admin.php`. Do not add a public password-reset endpoint unless a verified email/identity recovery process is implemented.


## InfinityFree browser recovery (no SSH required)

The public reset form is protected by a one-time key. Do not enable public reset without this key.

1. In InfinityFree, open **Control Panel → Online File Manager** (or FTP) and navigate to the same folder that contains `admin.html` and `admin_reset.php`.
2. Create a new file named exactly `admin_recovery_key.php` in that folder. Do not upload it into a public subfolder.
3. Generate a random secret key at least 40 characters long using a trusted password manager. Put this PHP content in the file, replacing the example text with your own key:

   ```php
   <?php
   return 'REPLACE-WITH-YOUR-OWN-RANDOM-KEY-AT-LEAST-40-CHARACTERS-LONG';
   ```

4. Save the file. Keep the key private and do not use the example phrase as your actual key.
5. Open your public `admin.html`, click **Forgot username / password?**, enter the exact key, and choose a new username and a unique password of at least 12 characters.
6. After a successful reset, `admin_reset.php` automatically deletes `admin_recovery_key.php`. If the file was not deleted, remove it manually in the file manager immediately.
7. Sign in using the new credentials. Existing reports and database settings are not deleted.

If your hosting account does not allow PHP files to be created or removed in this directory, use the hosting file manager/FTP to remove the recovery file after reset and contact the host about PHP write permissions. Never leave a recovery key file on the public server after use.


## InfinityFree first-time setup in the browser (no SSH, no XAMPP needed)

1. In InfinityFree **Online File Manager** open the folder containing `admin.html`.
2. Create a file named `admin_setup_key.php` with your own random key (40+ characters):

   ```php
   <?php
   return 'REPLACE-WITH-YOUR-OWN-RANDOM-KEY-AT-LEAST-40-CHARACTERS-LONG';
   ```
3. Open `admin.html`. The setup form now shows a **One-time setup key** field. Enter the key, choose a username and a password of 12+ characters.
4. On success the key file is deleted automatically (delete it manually if it remains). Sign in as usual.

On localhost nothing changes: no key is needed. Without the key file, hosted setup stays locked.

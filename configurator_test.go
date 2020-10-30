package a2conf

import (
	"strings"
	"testing"
)

func TestRemoveClosingVhostTag(t *testing.T) {
	type testData struct {
		originBlock,
		handledBlock string
	}

	items := []testData{
		{`<VirtualHost *:80>
				ServerName example.com
				ServerAlias www.example.com

				DocumentRoot /var/www/example.com

				<Directory /var/www/example.com>
					Options Indexes FollowSymlinks
					AllowOverride All
					Require all granted
				</Directory>

				DirectoryIndex index.html

				ErrorLog ${APACHE_LOG_DIR}/error.log
				CustomLog ${APACHE_LOG_DIR}/access.log combined
			</VirtualHost>`, `
			<VirtualHost *:80>
				ServerName example.com
				ServerAlias www.example.com

				DocumentRoot /var/www/example.com

				<Directory /var/www/example.com>
					Options Indexes FollowSymlinks
					AllowOverride All
					Require all granted
				</Directory>

				DirectoryIndex index.html

				ErrorLog ${APACHE_LOG_DIR}/error.log
				CustomLog ${APACHE_LOG_DIR}/access.log combined
		`},
		{`<VirtualHost *:80>
				ServerName example.com
				ServerAlias www.example.com

				DocumentRoot /var/www/example.com

				<Directory /var/www/example.com>
					Options Indexes FollowSymlinks
					AllowOverride All
					Require all granted
				</Directory>

				DirectoryIndex index.html

				ErrorLog ${APACHE_LOG_DIR}/error.log
				CustomLog ${APACHE_LOG_DIR}/access.log combined
			</VirtualHost> some additional data`, `
			<VirtualHost *:80>
				ServerName example.com
				ServerAlias www.example.com

				DocumentRoot /var/www/example.com

				<Directory /var/www/example.com>
					Options Indexes FollowSymlinks
					AllowOverride All
					Require all granted
				</Directory>

				DirectoryIndex index.html

				ErrorLog ${APACHE_LOG_DIR}/error.log
				CustomLog ${APACHE_LOG_DIR}/access.log combined
		`},
	}

	for _, item := range items {
		lines := strings.Split(item.originBlock, "\n")
		removeClosingVhostTag(lines)

		if strings.TrimSpace(item.handledBlock) != strings.TrimSpace(strings.Join(lines, "\n")) {
			t.Error("invalid content after tag deletion")
			t.Log(strings.Join(lines, "\n"))
			t.Log(item.handledBlock)
		}
	}
}

func TestIsRewriteRuleDangerousForSsl(t *testing.T) {
	type testData struct {
		line        string
		isDangerous bool
	}

	items := []testData{
		{"RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]", true},
		{"RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]", false},
		{"SomeRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]", false},
		{"RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI}", true},
		{"RewriteRule ^", false},
	}

	for _, item := range items {
		result := isRewriteRuleDangerousForSsl(item.line)

		if item.isDangerous != result {
			t.Errorf("expected %t, got %t", item.isDangerous, result)
		}
	}
}

func TestDisableDangerousForSslRewriteRules(t *testing.T) {
	type testData struct {
		content,
		expectedContent string
		skipped bool
	}

	items := []testData{
		{
			`<VirtualHost *:80>
				ServerName example.com
				ServerAlias www.example.com

				DocumentRoot /var/www/example.com

				<Directory /var/www/example.com>
					Options Indexes FollowSymlinks
					AllowOverride All
					Require all granted
				</Directory>

				RewriteCond %{HTTP_USER_AGENT} "=This Robot/1.0"
				RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]

				DirectoryIndex index.html

				RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
				RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]

				ErrorLog ${APACHE_LOG_DIR}/error.log
				CustomLog ${APACHE_LOG_DIR}/access.log combined

				RewriteCond %{HTTP_USER_AGENT} "=This Robot/1.0"
				RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
			</VirtualHost>`,
			`<VirtualHost *:80>
				ServerName example.com
				ServerAlias www.example.com

				DocumentRoot /var/www/example.com

				<Directory /var/www/example.com>
					Options Indexes FollowSymlinks
					AllowOverride All
					Require all granted
				</Directory>

# 				RewriteCond %{HTTP_USER_AGENT} "=This Robot/1.0"
# 				RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]

				DirectoryIndex index.html

# 				RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
				RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]

				ErrorLog ${APACHE_LOG_DIR}/error.log
				CustomLog ${APACHE_LOG_DIR}/access.log combined

				RewriteCond %{HTTP_USER_AGENT} "=This Robot/1.0"
				RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
			</VirtualHost>`,
			true,
		},
		{
			`<VirtualHost *:80>
				ServerName example.com
				ServerAlias www.example.com

				DocumentRoot /var/www/example.com

				<Directory /var/www/example.com>
					Options Indexes FollowSymlinks
					AllowOverride All
					Require all granted
				</Directory>

				DirectoryIndex index.html

				RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]

				ErrorLog ${APACHE_LOG_DIR}/error.log
				CustomLog ${APACHE_LOG_DIR}/access.log combined

				RewriteCond %{HTTP_USER_AGENT} "=This Robot/1.0"
				RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
			</VirtualHost>`,
			`<VirtualHost *:80>
				ServerName example.com
				ServerAlias www.example.com

				DocumentRoot /var/www/example.com

				<Directory /var/www/example.com>
					Options Indexes FollowSymlinks
					AllowOverride All
					Require all granted
				</Directory>

				DirectoryIndex index.html

				RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]

				ErrorLog ${APACHE_LOG_DIR}/error.log
				CustomLog ${APACHE_LOG_DIR}/access.log combined

				RewriteCond %{HTTP_USER_AGENT} "=This Robot/1.0"
				RewriteRule ^ http://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
			</VirtualHost>`,
			false,
		},
	}

	for _, item := range items {
		lines := strings.Split(strings.TrimSpace(item.content), "\n")
		nLines, skipped := disableDangerousForSslRewriteRules(lines)
		nContent := strings.TrimSpace(strings.Join(nLines, "\n"))
		expectedContent := strings.TrimSpace(item.expectedContent)

		if expectedContent != nContent {
			t.Error("invalid content after disabling dangerous for ssl rewrite rules")
			t.Log(expectedContent)
			t.Log(nContent)
		}

		if skipped != item.skipped {
			t.Errorf("invalid 'skipped' value, expected %t, got %t", item.skipped, skipped)
		}
	}
}

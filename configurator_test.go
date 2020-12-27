package a2conf

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/r2dtools/a2conf/entity"
	"github.com/stretchr/testify/assert"
	"github.com/unknwon/com"
)

const (
	apacheDir = "./test_data/apache"
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

func TestGetVhosts(t *testing.T) {
	configurator := getConfigurator(t)
	vhosts, err := configurator.GetVhosts()
	assert.Nilf(t, err, "could not get vhosts: %v", err)

	vhostsJSON, err := json.Marshal(vhosts)
	assert.Nilf(t, err, "could not marshal vhosts: %v", err)
	expectedVhostsJSON := getVhostsJSON(t)
	assert.Equal(t, expectedVhostsJSON, string(vhostsJSON), "invalid vhosts")
}

func TestFindSuitableVhost(t *testing.T) {
	configurator := getConfigurator(t)
	vhost := getVhost(t, configurator, "example2.com")
	assert.Equal(t, "example2.com", vhost.ServerName)
}

func TestGetVhostBlockContent(t *testing.T) {
	configurator := getConfigurator(t)
	vhost := getVhost(t, configurator, "example2.com")
	content, err := configurator.getVhostBlockContent(vhost)
	assert.Nilf(t, err, "could not get vhost block content: %v", err)
	expectedContent := getVhostConfigContent(t, "example2.com.conf")
	expectedContent = prepareStringToCompare(expectedContent)
	// getVhostBlockContent returns block without ending </VirtualHost>
	content = append(content, "</VirtualHost>")
	actualContent := strings.Join(content, "\n")
	actualContent = prepareStringToCompare(actualContent)

	assert.Equal(t, expectedContent, actualContent)
}

func TestGetSslVhostFilePath(t *testing.T) {
	configurator := getConfigurator(t)
	vhostPath := "/etc/apache2/sites-enabled/example2.com.conf"
	sslVhostPath, err := configurator.getSslVhostFilePath(vhostPath)
	assert.Nilf(t, err, "could not get ssl vhost file path: %v", err)
	assert.Equal(t, "/etc/apache2/sites-available/example2.com-ssl.conf", sslVhostPath)
}

func TestGetVhostNames(t *testing.T) {
	configurator := getConfigurator(t)
	vhostNames, err := configurator.getVhostNames("/files/etc/apache2/sites-enabled/example2.com.conf/VirtualHost")
	assert.Nilf(t, err, "could not get vhost names: %v", err)
	assert.Equal(t, "example2.com", vhostNames.ServerName)
	assert.Equal(t, 1, len(vhostNames.ServerAliases))
	assert.Equal(t, "www.example2.com", vhostNames.ServerAliases[0])
}

func TestGetDocumentRoot(t *testing.T) {
	configurator := getConfigurator(t)
	docRoot, err := configurator.getDocumentRoot("/files/etc/apache2/sites-enabled/example2.com.conf/VirtualHost")
	assert.Nilf(t, err, "could not get document root: %v", err)
	assert.Equal(t, "/var/www/html", docRoot)
}

func TestEnsurePortIsListening(t *testing.T) {
	configurator := getConfigurator(t)
	ports := []string{"80", "8080"}

	for _, port := range ports {
		err := configurator.EnsurePortIsListening(port, false)
		assert.Nilf(t, err, "failed to ensure that port '%s' is listening: %v", port, err)
	}
}

func TestMakeVhostSsl(t *testing.T) {
	configurator := getConfigurator(t)
	vhost := getVhost(t, configurator, "example2.com")
	sslVhost, err := configurator.MakeVhostSsl(vhost)
	assert.Nilf(t, err, "could not get ssl vhost: %v", err)
	sslConfigFilePath := "/etc/apache2/sites-available/example2.com-ssl.conf"
	assert.Equal(t, sslConfigFilePath, sslVhost.FilePath)
	// Check that ssl config file realy exists
	assert.Equal(t, true, com.IsFile(sslConfigFilePath))
	assert.Equal(t, vhost.ServerName, sslVhost.ServerName)
	assert.Equal(t, vhost.DocRoot, sslVhost.DocRoot)
	assert.Equal(t, true, sslVhost.Ssl)
	assert.Equal(t, false, sslVhost.Enabled)
	assert.Equal(t, false, sslVhost.ModMacro)

	// Check that addresses are corerct for ssl vhost
	var addresses []entity.Address
	for _, address := range sslVhost.Addresses {
		addresses = append(addresses, address)
	}

	assert.Equal(t, 1, len(addresses))
	assert.Equal(t, "*:443", addresses[0].ToString())
}

func getVhostsJSON(t *testing.T) string {
	vhostsPath := apacheDir + "/vhosts.json"
	assert.FileExists(t, vhostsPath, "could not open vhosts file")
	data, err := ioutil.ReadFile(vhostsPath)
	assert.Nilf(t, err, "could not read vhosts file: %v", err)

	return prepareStringToCompare(string(data))
}

func getConfigurator(t *testing.T) *ApacheConfigurator {
	configurator, err := GetApacheConfigurator(nil)
	assert.Nil(t, err, fmt.Sprintf("could not creatre apache configurator: %v", err))

	return configurator
}

func getVhost(t *testing.T, configurator *ApacheConfigurator, serverName string) *entity.VirtualHost {
	vhost, err := configurator.FindSuitableVhost(serverName, false)
	assert.Nilf(t, err, "could not find suitable vhost: %v", err)
	assert.NotNil(t, vhost)

	return vhost
}

func getVhostConfigContent(t *testing.T, name string) string {
	path := filepath.Join(apacheDir, name)
	content, err := ioutil.ReadFile(path)
	assert.Nilf(t, err, "could not read apache vhost config file '%s' content: %v", name, err)

	return string(content)
}

func prepareStringToCompare(str string) string {
	re := regexp.MustCompile(`[\r\n\s]`)
	return re.ReplaceAllString(string(str), "")
}

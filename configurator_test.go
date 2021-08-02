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
	vhosts := getVhosts(t, configurator, "example2.com")
	assert.Equal(t, "example2.com", vhosts[0].ServerName)
}

func TestGetVhostBlockContent(t *testing.T) {
	configurator := getConfigurator(t)
	vhosts := getVhosts(t, configurator, "example2.com")
	content, err := configurator.getVhostBlockContent(vhosts[0])
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

func TestGetSuitableVhostsSingle(t *testing.T) {
	type vhostItem struct {
		serverName, sslConfigFilePath, docRoot string
		ssl, enabled                           bool
	}

	configurator := getConfigurator(t)
	vhostItems := []vhostItem{
		{"example2.com", "/etc/apache2/sites-available/example2.com-ssl.conf", "/var/www/html", true, false},
		{"example.com", "/etc/apache2/sites-enabled/example-ssl.com.conf", "/var/www/html", true, true},
	}

	for _, vhostItem := range vhostItems {
		sslVhosts, err := configurator.GetSuitableVhosts(vhostItem.serverName, true)
		assert.Nilf(t, err, "could not get ssl vhost: %v", err)
		assert.Equal(t, 1, len(sslVhosts))
		sslVhost := sslVhosts[0]
		assert.Equal(t, vhostItem.sslConfigFilePath, sslVhost.FilePath)
		// Check that ssl config file realy exists
		assert.Equal(t, true, com.IsFile(vhostItem.sslConfigFilePath))
		assert.Equal(t, vhostItem.serverName, sslVhost.ServerName)
		assert.Equal(t, vhostItem.docRoot, sslVhost.DocRoot)
		assert.Equal(t, vhostItem.ssl, sslVhost.Ssl)
		assert.Equal(t, vhostItem.enabled, sslVhost.Enabled)
		assert.Equal(t, false, sslVhost.ModMacro)

		// Check that addresses are corerct for ssl vhost
		var addresses []entity.Address
		for _, address := range sslVhost.Addresses {
			addresses = append(addresses, address)
		}

		assert.Equal(t, 1, len(addresses))
		assert.Equal(t, "*:443", addresses[0].ToString())
	}
}

func TestGetSuitableVhostsMultiple(t *testing.T) {
	configurator := getConfigurator(t)
	sslVhosts, err := configurator.GetSuitableVhosts("example4.com", true)
	assert.Nilf(t, err, "could not get ssl vhost: %v", err)
	assert.Equal(t, 2, len(sslVhosts))
	addresses := []string{"[2002:5bcc:18fd:c:10:52:43:96]", "10.52.43.96"}

	for _, sslVhost := range sslVhosts {
		assert.Equal(t, "/etc/apache2/sites-enabled/example4-ssl.com.conf", sslVhost.FilePath)
		// Check that ssl config file realy exists
		assert.Equal(t, true, com.IsFile("/etc/apache2/sites-enabled/example4-ssl.com.conf"))
		assert.Equal(t, "example4.com", sslVhost.ServerName)
		assert.Equal(t, "/var/www/html", sslVhost.DocRoot)
		assert.Equal(t, true, sslVhost.Ssl)
		assert.Equal(t, true, sslVhost.Enabled)
		assert.Equal(t, false, sslVhost.ModMacro)
		assert.Equal(t, 1, len(sslVhost.Addresses))
		assert.Equal(t, true, com.IsSliceContainsStr(addresses, sslVhost.GetAddressesString(true)))
	}
}

func TestDeployCertificate(t *testing.T) {
	configurator := getConfigurator(t)
	err := configurator.DeployCertificate("example5.com", "/opt/a2conf/test_data/apache/certificate/example.com.crt", "/opt/a2conf/test_data/apache/certificate/example.com.key", "", "/opt/a2conf/test_data/apache/certificate/example.com.crt")
	assert.Nilf(t, err, "could not deploy certificate to vhost: %v", err)
	err = configurator.Save()
	assert.Nilf(t, err, "could not save changes after certificate deploy: %v", err)
	assert.Equal(t, true, configurator.CheckConfiguration())
	err = configurator.Commit()
	assert.Nilf(t, err, "could not commit changes after certificate deploy: %v", err)
	err = configurator.RestartWebServer()
	assert.Nilf(t, err, "could not restart webserver after certificate deploy: %v", err)
	// Check that ssl config file realy exists
	sslConfigFilePath := "/etc/apache2/sites-enabled/example5.com-ssl.conf"
	assert.Equal(t, true, com.IsFile(sslConfigFilePath))

	sslConfigContent, err := ioutil.ReadFile(sslConfigFilePath)
	assert.Nilf(t, err, "could not read apache vhost ssl config file '%s' content: %v", sslConfigFilePath, err)
	directives := []string{"SSLCertificateKeyFile /opt/a2conf/test_data/apache/certificate/example.com.key", "SSLEngine on", "SSLCertificateFile /opt/a2conf/test_data/apache/certificate/example.com.crt"}

	for _, directive := range directives {
		assert.Containsf(t, string(sslConfigContent), directive, "ssl config does not contain directive '%s'", directive)
	}
}

func getVhostsJSON(t *testing.T) string {
	vhostsPath := apacheDir + "/vhosts.json"
	assert.FileExists(t, vhostsPath, "could not open vhosts file")
	data, err := ioutil.ReadFile(vhostsPath)
	assert.Nilf(t, err, "could not read vhosts file: %v", err)

	return prepareStringToCompare(string(data))
}

func getConfigurator(t *testing.T) *apacheConfigurator {
	configurator, err := GetApacheConfigurator(nil)
	assert.Nil(t, err, fmt.Sprintf("could not creatre apache configurator: %v", err))

	return configurator.(*apacheConfigurator)
}

func getVhosts(t *testing.T, configurator ApacheConfigurator, serverName string) []*entity.VirtualHost {
	vhosts, err := configurator.FindSuitableVhosts(serverName)
	assert.Nilf(t, err, "could not find suitable vhost: %v", err)
	assert.NotEmptyf(t, vhosts, "could not find suitable vhost for '%s' servername", serverName)

	return vhosts
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

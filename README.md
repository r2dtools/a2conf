# a2conf
With the help of the library, you can manage the configs of the virtual hosts of the apache web server. For example, you can get a list of virtual hosts, or install a certificate on a virtual host. Under the hood, a2conf works with configs using the [augeas](https://augeas.net/) library.

## Installation
```bash
go get r2dtools/a2conf
```

## Load virtual hosts
```go
import (
	"encoding/json"
	"fmt"

	"github.com/r2dtools/a2conf"
)

func main() {
	configurator, err := a2conf.GetApacheConfigurator(nil)

	if err != nil {
		panic(fmt.Sprintf("could not create apache configurator: %v", err))
	}

	vhosts, err := configurator.GetVhosts()

	if err != nil {
		panic(fmt.Sprintf("could not get virtual hosts: %v", err))
	}

	jsonVhosts, _ := json.Marshal(vhosts)
	fmt.Printf("vhsosts: %v", string(jsonVhosts))
}
```

## Install a certificate on a virtual host
```go
import (
	"encoding/json"
	"fmt"

	"github.com/r2dtools/a2conf"
)

func main() {
	configurator, err := a2conf.GetApacheConfigurator(nil)

	if err != nil {
		panic(fmt.Sprintf("could not create apache configurator: %v", err))
	}
	
	if err := configurator.DeployCertificate("example.com", "certPath", "certKeyPath", "chainPath", "fullChainPath"); err != nil {
		rollback(configurator)
		return fmt.Errorf("could not deploy certificate to virtual host '%s': %v", vhost.ServerName, err)
	}

	if err := configurator.Save(); err != nil {
		message := fmt.Sprintf("could not deploy certificate for virtual host '%s': could not save changes for apache configuration: %v", vhost.ServerName, err)
		rollback(configurator)

		return fmt.Errorf(message)
	}

	if !configurator.CheckConfiguration() {
		message := fmt.Sprintf("could not deploy certificate for virtual host '%s': apache configuration is invalid.", vhost.ServerName)
		rollback(configurator)

		return fmt.Errorf(message)
	}

	if err := configurator.Commit(); err != nil {
		return err
	}

	if err := configurator.RestartWebServer(); err != nil {
		return err
	}
}

func rollback(configurator a2conf.ApacheConfigurator) {
	if err := configurator.Rollback(); err != nil {
		logger.Error(fmt.Sprintf("could not rollback apache configuration: %v", err))
	}
}
```

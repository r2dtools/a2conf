# a2conf
Parse and manipulate with apache2 config using augeas library

## Installation
```bash
go get r2dtools/a2conf
```

## Example
```go
import (
	"encoding/json"
	"fmt"

	"github.com/r2dtools/a2conf/a2conf"
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

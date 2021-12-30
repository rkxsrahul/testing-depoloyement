package nats

import (
	"log"

	"git.xenonstack.com/akirastack/continuous-security-deployments/config"
)

type RequestData struct {
	Data   map[string]interface{} `json:"data"`
	UUID   string                 `json:"uuid"`
	Method string                 `json:"method"`
	Header string                 `json:"header"`
	Status bool                   `json:"status"`
}

func Publish(data []byte, subject string) {
	log.Println(string(data), subject)
	if err := config.NC.Publish("scan-results", data); err != nil {
		log.Fatal(err)
	}
}
func GitScanPublish(data []byte, subject string) {
	log.Println(string(data), subject)
	if err := config.NC.Publish("git-scan-results", data); err != nil {
		log.Fatal(err)
	}
}

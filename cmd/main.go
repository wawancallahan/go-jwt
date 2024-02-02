package main

import (
	"log"

	"github.com/wawancallahan/go-jwt/config"
)

func main() {
	token := config.GenerateJwtToken()

	log.Println(token)

	validate, err := config.ValidateJwtTokenClaims(token)

	if err != nil {
		log.Fatal("Error Validate Token", err.Error())
	}

	if validate != nil {
		log.Println(validate.UserName)
	}
}

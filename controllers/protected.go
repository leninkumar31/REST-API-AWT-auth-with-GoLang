package controllers

import (
	"net/http"

	"../utils"
)

type Controller struct{}

func (c Controller) ProtectedEndPoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		utils.ResponseJSON(w, "Yes")
	}
}

package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"../models"
	userRepository "../repository/user"
	"../utils"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func (c Controller) SignUp(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var err models.Error
		json.NewDecoder(r.Body).Decode(&user)
		if user.Email == "" {
			err.Message = "Email is missing"
			utils.RespondWithError(w, http.StatusBadRequest, err)
			return
		}

		if user.Password == "" {
			err.Message = "Password is missing"
			utils.RespondWithError(w, http.StatusBadRequest, err)
			return
		}

		hash, error := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if error != nil {
			log.Fatal(error)
		}
		user.Password = string(hash)
		userRepo := userRepository.UserRepository{}
		user = userRepo.SignUp(db, user)
		if error != nil {
			err.Message = "Server Error!"
			utils.RespondWithError(w, http.StatusInternalServerError, err)
			return
		}
		user.Password = ""
		w.Header().Set("Content-Type", "application/json")
		utils.ResponseJSON(w, user)
	}
}

func (c Controller) Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var jwt models.JWT
		var error models.Error

		json.NewDecoder(r.Body).Decode(&user)
		password := user.Password
		if user.Email == "" {
			error.Message = "Email is missing"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		}

		if user.Password == "" {
			error.Message = "Password is missing"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		}

		userRepo := userRepository.UserRepository{}
		user, err := userRepo.Login(db, user)

		if err != nil {
			if err == sql.ErrNoRows {
				error.Message = "the user doesnt exist"
				utils.RespondWithError(w, http.StatusBadRequest, error)
				return
			} else {
				log.Fatal(err)
			}
		}
		hashedPassword := user.Password
		if !utils.ComparePasswords(hashedPassword, []byte(password)) {
			error.Message = "Invalid Password"
			utils.RespondWithError(w, http.StatusUnauthorized, error)
			return
		}
		token, err := utils.GenerateToken(user)
		if err != nil {
			log.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
		jwt.Token = token
		utils.ResponseJSON(w, jwt)
	}
}

func (c Controller) TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(os.Getenv("SECRET")), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid token"
			utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})
}

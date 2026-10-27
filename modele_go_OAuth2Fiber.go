package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Structure adaptée pour l'API UserInfo v3
type GoogleUser struct {
	ID      string `json:"sub"` // En API v3 / OpenID Connect, l'ID unique est sous la clé "sub"
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func main() {
	// Initialisation de Fiber v3
	app := fiber.New()

	conf := &oauth2.Config{
		ClientID:     "TON_CLIENT_ID.apps.googleusercontent.com",
		ClientSecret: "TON_CLIENT_SECRET",
		RedirectURL:  "http://localhost:3000/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// 1. Redirection vers Google (Génération sécurisée du State)
	app.Get("/auth/google/login", func(c fiber.Ctx) error {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		stateToken := hex.EncodeToString(b)

		// On stocke le state dans un cookie temporaire
		c.Cookie(&fiber.Cookie{
			Name:     "state_auth",
			Value:    stateToken,
			HTTPOnly: true,
			SameSite: "Lax",
			Secure:   false, // Mettre à true en production (HTTPS)
			Expires:  time.Now().Add(15 * time.Minute),
		})

		// Redirection (Syntaxe Fiber v3)
		url := conf.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)
		return c.Redirect().To(url)
	})

	// 2. Le Callback : Vérification anti-CSRF, Échange et Session
	app.Get("/auth/google/callback", func(c fiber.Ctx) error {
		code := c.Query("code")
		receivedState := c.Query("state")
		expectedState := c.Cookies("state_auth")

		// Vérification de sécurité anti-CSRF
		if code == "" || receivedState == "" || receivedState != expectedState {
			return c.Status(fiber.StatusBadRequest).SendString("Erreur de sécurité : State invalide ou code manquant !")
		}

		ctx := context.Background()

		// Échange du code contre le token
		token, err := conf.Exchange(ctx, code)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).SendString("Échec de l'échange du token")
		}

		client := conf.Client(ctx, token)

		// A. Récupération des infos du profil via l'API UserInfo V3
		resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Erreur profil Google")
		}
		defer resp.Body.Close()

		var user GoogleUser
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Erreur de décodage du profil")
		}

		// B. Téléchargement optionnel du binaire de l'image de profil
		if user.Picture != "" {
			imgResp, err := client.Get(user.Picture)
			if err == nil {
				defer imgResp.Body.Close()
				imageBytes, _ := io.ReadAll(imgResp.Body)
				fmt.Printf("Image de profil téléchargée pour %s ! ID unique (sub) : %s | Taille : %d octets\n", user.Email, user.ID, len(imageBytes))
			}
		}

		// C. Cookie HTTPOnly de session
		c.Cookie(&fiber.Cookie{
			Name:     "session_token",
			Value:    token.AccessToken,
			Expires:  time.Now().Add(24 * time.Hour * 31),
			HTTPOnly: true,
			Secure:   false, // Mettre à true en production (HTTPS)
			SameSite: "Lax",
		})

		return c.SendString(fmt.Sprintf("Connexion réussie pour %s !\nID unique Google (sub) : %s\nSécurité CSRF validée.", user.Email, user.ID))
	})

	log.Fatal(app.Listen(":3000"))
}

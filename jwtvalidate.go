package main

import (
    "context"
    "fmt"
    "github.com/golang-jwt/jwt"
    "github.com/lestrrat-go/jwx/jwk"
)

// Replace YOUR_JWKS_URL with the actual URL to your JWKS endpoint
const JWKS_URL = "YOUR_JWKS_URL"

func main() {
    // Sample JWT token you want to validate
    tokenString := "YOUR_JWT_TOKEN"

    // Fetch JWKS from the endpoint
    set, err := jwk.Fetch(context.Background(), JWKS_URL)
    if err != nil {
        panic("failed to parse JWK: " + err.Error())
    }

    // Parse the JWT token
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Ensure the JWT algorithm matches the expected algorithm
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }

        // Find the key ID in the token header
        keyID, ok := token.Header["kid"].(string)
        if !ok {
            return nil, fmt.Errorf("expecting JWT header to have string kid")
        }

        // Find the corresponding key in the JWKS
        if key := set.LookupKeyID(keyID); len(key) == 1 {
            var pubkey interface{}
            if err := key[0].Raw(&pubkey); err == nil {
                return pubkey, nil
            }
        }

        return nil, fmt.Errorf("unable to find the appropriate key")
    })

    if err != nil {
        fmt.Println("Error parsing token:", err)
        return
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        fmt.Println("JWT is valid. Claims:", claims)
    } else {
        fmt.Println("Invalid JWT")
    }
}


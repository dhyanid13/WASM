package main

import (
    "context"
    "fmt"
    "github.com/golang-jwt/jwt/v4" // Ensure you're using the jwt/v4 for updated API
    "github.com/lestrrat-go/jwx/jwk"
)

const JWKS_URL = "YOUR_JWKS_URL" // Replace with your JWKS URL

func main() {
    tokenString := "YOUR_JWT_TOKEN" // Replace with the JWT you want to validate

    // Fetch JWKS
    set, err := jwk.Fetch(context.Background(), JWKS_URL)
    if err != nil {
        panic(fmt.Errorf("failed to parse JWK: %w", err))
    }

    // Parse and validate the JWT
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Confirm the JWT algorithm
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }

        // Extract the key ID from the JWT header
        keyID, ok := token.Header["kid"].(string)
        if !ok {
            return nil, fmt.Errorf("expecting JWT header to have string 'kid'")
        }

        // Lookup the key in JWKS
        key, found := set.LookupKeyID(keyID)
        if !found {
            return nil, fmt.Errorf("unable to find the appropriate key")
        }

        // Extract the public key
        var pubkey interface{}
        if err := key.Raw(&pubkey); err != nil {
            return nil, fmt.Errorf("failed to get raw key: %v", err)
        }

        return pubkey, nil
    })

    if err != nil {
        fmt.Printf("Error parsing token: %v\n", err)
        return
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        fmt.Printf("JWT is valid. Claims: %v\n", claims)
    } else {
        fmt.Println("Invalid JWT")
    }
}

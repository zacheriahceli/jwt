package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Parser is a helper for parsing and validating tokens.
type Parser struct {
	ValidMethods         []string // If populated, only these methods will be considered valid
	UseAlias             bool     // Use the alias for the claims if it exists
	SkipClaimsValidation bool     // Skip claims validation
}

// NewParser creates a new Parser instance.
func NewParser(options ...ParserOption) *Parser {
	p := &Parser{}
	for _, option := range options {
		option(p)
	}
	return p
}

// ParserOption is a function that configures a Parser.
type ParserOption func(*Parser)

// WithValidMethods configures the parser to only accept the specified signing methods.
func WithValidMethods(methods []string) ParserOption {
	return func(p *Parser) {
		p.ValidMethods = methods
	}
}

// Parse parses, validates, and returns a token.
// keyFunc will receive the parsed token and should return the key for validating the signature.
func (p *Parser) Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return p.ParseWithClaims(tokenString, MapClaims{}, keyFunc)
}

// ParseWithClaims parses, validates, and returns a token with custom claims.
// keyFunc will receive the parsed token and should return the key for validating the signature.
func (p *Parser) ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error) {
	token, parts, err := p.ParseUnverified(tokenString, claims)
	if err != nil {
		return token, err
	}

	// Verify signing method is in the allowed list
	if p.ValidMethods != nil {
		var isAllowed bool
		for _, m := range p.ValidMethods {
			if m == token.Method.Alg() {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return token, NewValidationError(fmt.Sprintf("signing method %v is invalid", token.Method.Alg()), ValidationErrorSignatureInvalid)
		}
	}

	// Lookup key
	if keyFunc == nil {
		return token, NewValidationError("no keyfunc was provided", ValidationErrorUnverifiable)
	}

	key, err := keyFunc(token)
	if err != nil {
		return token, NewValidationError(err.Error(), ValidationErrorUnverifiable)
	}

	// Verify signature
	sig, err := DecodeSegment(parts[2])
	if err != nil {
		return token, NewValidationError(err.Error(), ValidationErrorMalformed)
	}

	err = token.Method.Verify(strings.Join(parts[0:2], "."), sig, key)
	if err != nil {
		return token, NewValidationError(err.Error(), ValidationErrorSignatureInvalid)
	}

	// Validate claims
	if !p.SkipClaimsValidation {
		if err := token.Claims.Valid(); err != nil {
			return token, NewValidationError(err.Error(), ValidationErrorClaimsInvalid)
		}
	}

	token.Valid = true
	return token, nil
}

// ParseUnverified parses the token but does not validate the signature.
func (p *Parser) ParseUnverified(tokenString string, claims Claims) (*Token, []string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, NewValidationError("token contains an invalid number of segments", ValidationErrorMalformed)
	}

	// Parse Header
	headerBytes, err := DecodeSegment(parts[0])
	if err != nil {
		return nil, nil, NewValidationError(err.Error(), ValidationErrorMalformed)
	}

	var header map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(headerBytes))
	if err := dec.Decode(&header); err != nil {
		return nil, nil, NewValidationError(err.Error(), ValidationErrorMalformed)
	}

	// Parse Claims
	claimsBytes, err := DecodeSegment(parts[1])
	if err != nil {
		return nil, nil, NewValidationError(err.Error(), ValidationErrorMalformed)
	}

	dec = json.NewDecoder(bytes.NewReader(claimsBytes))
	if p.UseAlias {
		// Custom decoding logic if UseAlias is set
	}
	if err := dec.Decode(&claims); err != nil {
		return nil, nil, NewValidationError(err.Error(), ValidationErrorMalformed)
	}

	// Lookup signature method
	alg, ok := header["alg"].(string)
	if !ok {
		return nil, nil, NewValidationError("signing method (alg) is missing or invalid", ValidationErrorMalformed)
	}

	method := GetSigningMethod(alg)
	if method == nil {
		return nil, nil, NewValidationError(fmt.Sprintf("signing method %v is unknown", alg), ValidationErrorUnverifiable)
	}

	token := &Token{
		Raw:    tokenString,
		Header: header,
		Claims: claims,
		Method: method,
	}

	return token, parts, nil
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	vaultApi "github.com/hashicorp/vault/api"
)

const (
	env             string = "dev"
	vaultAuthHeader string = "vault.example.com"
)

var (
	vaultAddr        string = fmt.Sprintf("http://vault-%s.example.com", env)
	service          string
	vaultClient      *vaultApi.Client
	token            string
	tokenIsRenewable bool
	tokenExpiration  time.Time     // actual expiration
	tokenTTL         time.Duration // lifetime of the auth token received
	expirationWindow time.Duration // time to allow to process a token renewal
	renewalWindow    time.Duration // time before expiration when token should be actively renewed
	format           string
)

type VaultLock struct {
	Expiry      string `json:"expiry"`
	Env         string `json:"env"`
	LeaseId     string `json:"lease_id"`
	ServiceType string `json:"service_type"`
	Username    string `json:"username"`
	DbUser      string `json:"dbuser"`
}

func main() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	flagset := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { flagset[f.Name] = true })

	iamClient := iam.New(sess, &aws.Config{Region: aws.String("us-east-1")})
	_, err := iamClient.GetUser(nil)
	if err != nil {
		fmt.Printf("Failed to get IAM user - %s\n", err)
	}

	_, err = VaultClient()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// VaultClient() returns a configured and authenticated Vault client object. If
// the client does not yet exist, it is created and authenticated. If it does
// exist but the token is expired or near expiration, the token will be renewed
// if possible, or a new token will be acquired.
func VaultClient() (*vaultApi.Client, error) {

	expirationWindow = time.Duration(10) * time.Second

	// should be at least the length of the lambda runtime
	renewalWindow = time.Duration(300) * time.Second

	vaultClient, _ = vaultApi.NewClient(&vaultApi.Config{
		Address: vaultAddr,
	})

	if isExpired() {
		return vaultClient, VaultAuth()
	}

	if shouldRenew() {
		return vaultClient, RenewToken()
	}

	return vaultClient, nil
}

// Renew the token if it is renewable. If it isn't, or if it's expired, refresh
// authentication instead. This is typically called internally.
func RenewToken() error {
	if isExpired() || !tokenIsRenewable {
		return VaultAuth()
	}

	resp, err := vaultClient.Auth().Token().RenewSelf(int(tokenTTL))
	if err != nil {
		return err
	}

	return parseToken(resp)
}

func isExpired() bool {
	return time.Now().Add(expirationWindow).After(tokenExpiration)
}

func shouldRenew() bool {
	return time.Now().Add(renewalWindow).After(tokenExpiration)
}

// Call VaultAuth() to authenticate the Lambda execution role to the Vault auth
// context specified by the VAULT_ADDR, VAULT_AUTH_PROVIDER, and VAULT_AUTH_ROLE
// environment variables. If no error is returned, then VaultClient is ready to
// go. This function is typically called internally.
//
// This code was adapted from Hashicorp Vault:
//
//	https://github.com/hashicorp/vault/blob/e2bb2ec3b93a242a167f763684f93df867bb253d/builtin/credential/aws/cli.go#L78
func VaultAuth() error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	stsClient := sts.New(sess, &aws.Config{Region: aws.String("us-east-1")})

	req, _ := stsClient.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	req.HTTPRequest.Header.Add("X-Vault-AWS-IAM-Server-ID", vaultAuthHeader)

	req.Sign()

	headers, err := json.Marshal(req.HTTPRequest.Header)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	body, err := io.ReadAll(req.HTTPRequest.Body)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	d := make(map[string]interface{})
	d["iam_http_request_method"] = req.HTTPRequest.Method
	d["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(req.HTTPRequest.URL.String()))
	d["iam_request_headers"] = base64.StdEncoding.EncodeToString(headers)
	d["iam_request_body"] = base64.StdEncoding.EncodeToString(body)

	if err != nil {
		fmt.Printf("Error initializing vault connection - %s\n", err)
	}
	resp, err := vaultClient.Logical().Write(fmt.Sprintf("auth/aws/login"), d)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if resp == nil {
		fmt.Println("Got no response from the aws authentication provider")
		os.Exit(1)
	}

	return parseToken(resp)
}

func parseToken(resp *vaultApi.Secret) error {
	var err error
	if token, err = resp.TokenID(); err != nil {
		return err
	}

	if tokenIsRenewable, err = resp.TokenIsRenewable(); err != nil {
		return err
	}

	if tokenTTL, err = resp.TokenTTL(); err != nil {
		return err
	}
	tokenExpiration = time.Now().Add(tokenTTL)

	vaultClient.SetToken(token)

	return nil
}

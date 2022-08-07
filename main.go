package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	dilithium "github.com/kudelskisecurity/crystals-go/crystals-dilithium"
	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
	"github.com/mariiatuzovska/logger"
	"github.com/urfave/cli"
)

var (
	ServiceName = "crystals-kyber"
	Version     = "1.0"

	log logger.LoggerService
)

const fatalExitCode = 1

func main() {
	app := cli.NewApp()
	app.Name = serviceNameVithVersion()
	app.Usage = "command line client"
	app.Description = "crystals-kyber encryption/decryption service"
	app.Version = Version
	app.Authors = []cli.Author{{Name: "Tuzovska Mariia", Email: "mariia.tuzovska@gmail.com"}}
	app.Commands = []cli.Command{
		{
			Name:    "kyber",
			Aliases: []string{"k"},
			Usage:   "Kyber algorithms kyber512/kyber768/kyber1024",
			Subcommands: []cli.Command{
				{
					Name:    "key-gen",
					Aliases: []string{"k"},
					Action: func(c *cli.Context) error {
						setLog(c)
						log.Info("Generating [kyber] public and secret keys has been started")
						k := getKyberAlg(c)
						seed := getSeed(c)
						pk, sk := k.PKEKeyGen(seed)
						log.Info("Kyber keys have been generated")
						base64PK, base64SK := base64.StdEncoding.EncodeToString(pk), base64.StdEncoding.EncodeToString(sk)
						fmt.Println("Public key:", base64PK, "\n")
						fmt.Println("Secret key:", base64SK, "\n")
						return nil
					},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "alg",
							Usage: "Algorithm name (kyber512/kyber768/kyber1024)",
						},
						&cli.StringFlag{
							Name:  "seed",
							Usage: "32 bytes encoded to base64 string seed",
						},
						&cli.StringFlag{
							Name:  "log-level",
							Usage: "Log level (DEBUG/INFO/WARNING/ERROR/FATAL)",
							Value: "ERROR",
						},
					},
				},
				{
					Name:    "encrypt",
					Aliases: []string{"e", "enc"},
					Action: func(c *cli.Context) error {
						setLog(c)
						log.Info("Encryption [kyber] has been started")
						k := getKyberAlg(c)
						pk, err := base64.StdEncoding.DecodeString(c.String("public-key"))
						if err != nil {
							log.Fatal("Unknown flag value: public-key is malformed", fatalExitCode)
						}
						seed := getSeed(c)
						encrypted := k.Encrypt(pk, []byte(c.String("message")), seed)
						base64EncryptedMSg := base64.StdEncoding.EncodeToString(encrypted)
						fmt.Println("Ciphertext:", base64EncryptedMSg)
						log.Info("Message has been encrypted")
						return nil
					},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "alg",
							Usage: "Algorithm name (kyber512/kyber768/kyber1024)",
							Value: "kyber768",
						},
						&cli.StringFlag{
							Name:  "seed",
							Usage: "32 bytes encoded to base64 string seed",
						},
						&cli.StringFlag{
							Name:     "public-key",
							Usage:    "Base64 encoded public key",
							Required: true,
						},
						&cli.StringFlag{
							Name:     "message",
							Usage:    "Message must be more then 256 bytes",
							Required: true,
						},
						&cli.StringFlag{
							Name:  "log-level",
							Usage: "Log level (DEBUG/INFO/WARNING/ERROR/FATAL)",
							Value: "ERROR",
						},
					},
				},
				{
					Name:    "decrypt",
					Aliases: []string{"d", "dec"},
					Action: func(c *cli.Context) error {
						setLog(c)
						log.Info("Decryption [kyber] has been started")
						k := getKyberAlg(c)
						pk, err := base64.StdEncoding.DecodeString(c.String("secret-key"))
						if err != nil {
							log.Fatal("Unknown flag value: secret-key is malformed", fatalExitCode)
						}
						ciphertext, err := base64.StdEncoding.DecodeString(c.String("ciphertext"))
						if err != nil {
							log.Fatal("Unknown flag value: ciphertext is malformed", fatalExitCode)
						}
						decrypted := k.Decrypt(pk, ciphertext)
						fmt.Println("Plaintext:", string(decrypted))
						log.Info("Message has been decrypted")
						return nil
					},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "alg",
							Usage: "Algorithm name (kyber512/kyber768/kyber1024)",
							Value: "kyber768",
						},
						&cli.StringFlag{
							Name:  "log-level",
							Usage: "Log level (DEBUG/INFO/WARNING/ERROR/FATAL)",
							Value: "ERROR",
						},
						&cli.StringFlag{
							Name:     "secret-key",
							Usage:    "Base64 encoded secret key",
							Required: true,
						},
						&cli.StringFlag{
							Name:     "ciphertext",
							Usage:    "Encrypted message",
							Required: true,
						},
					},
				},
			},
		},
		{
			Name:    "dilithium",
			Aliases: []string{"d"},
			Usage:   "Dilithium algorithms kyber512/kyber768/kyber1024",
			Subcommands: []cli.Command{
				{
					Name:    "key-gen",
					Aliases: []string{"k"},
					Action: func(c *cli.Context) error {
						setLog(c)
						log.Info("Generating [dilithium] public and secret keys has been started")
						d := getDilithiumAlg(c)
						seed := getSeed(c)
						pk, sk := d.KeyGen(seed)
						base64PK, base64SK := base64.StdEncoding.EncodeToString(pk), base64.StdEncoding.EncodeToString(sk)
						fmt.Println("Public key:", base64PK, "\n")
						fmt.Println("Secret key:", base64SK, "\n")
						log.Info("Dilithium keys have been generated")
						return nil
					},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "alg",
							Usage: "Algorithm name (dilithium2/dilithium3/dilithium5)",
							Value: "dilithium3",
						},
						&cli.StringFlag{
							Name:  "seed",
							Usage: "32 bytes encoded to base64 string seed",
						},
						&cli.StringFlag{
							Name:  "log-level",
							Usage: "Log level (DEBUG/INFO/WARNING/ERROR/FATAL)",
							Value: "ERROR",
						},
					},
				},
				{
					Name:    "sign",
					Aliases: []string{"s"},
					Action: func(c *cli.Context) error {
						setLog(c)
						log.Info("Signing [dilithium] message has been started")
						d := getDilithiumAlg(c)
						sk, err := base64.StdEncoding.DecodeString(c.String("secret-key"))
						if err != nil {
							log.Fatal("Unknown flag value: public-key is malformed", fatalExitCode)
						}
						log.Info("Secret key has been read")
						signature := d.Sign(sk, []byte(c.String("message")))
						base64OfSignature := base64.StdEncoding.EncodeToString(signature)
						fmt.Println("Signature:", base64OfSignature, "\n")
						log.Info("Signature has been created")
						return nil
					},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "alg",
							Usage: "Algorithm name (kyber512/kyber768/kyber1024)",
							Value: "kyber768",
						},
						&cli.StringFlag{
							Name:  "log-level",
							Usage: "Log level (DEBUG/INFO/WARNING/ERROR/FATAL)",
							Value: "ERROR",
						},
						&cli.StringFlag{
							Name:     "secret-key",
							Usage:    "Base64 encoded secret key",
							Required: true,
						},
						&cli.StringFlag{
							Name:     "message",
							Required: true,
						},
					},
				},
				{
					Name:    "verify",
					Aliases: []string{"v"},
					Action: func(c *cli.Context) error {
						setLog(c)
						log.Info("Verifying [dilithium] message has been started")
						d := getDilithiumAlg(c)
						pk, err := base64.StdEncoding.DecodeString(c.String("public-key"))
						if err != nil {
							log.Fatal("Unknown flag value: public-key is malformed", fatalExitCode)
						}
						log.Info("Public key has been read")
						sgn, err := base64.StdEncoding.DecodeString(c.String("signature"))
						if err != nil {
							log.Fatal("Unknown flag value: signature is malformed", fatalExitCode)
						}
						log.Info("Signature has been read")
						ok := d.Verify(pk, []byte(c.String("message")), sgn)
						if ok {
							fmt.Println("Signature verified: ok")
						} else {
							fmt.Println("Signature verified: signature is not valid")
						}
						log.Info("Signature has been verified")
						return nil
					},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "alg",
							Usage: "Algorithm name (kyber512/kyber768/kyber1024)",
							Value: "kyber768",
						},
						&cli.StringFlag{
							Name:  "log-level",
							Usage: "Log level (DEBUG/INFO/WARNING/ERROR/FATAL)",
							Value: "ERROR",
						},
						&cli.StringFlag{
							Name:     "public-key",
							Usage:    "Base64 encoded public key",
							Required: true,
						},
						&cli.StringFlag{
							Name:     "message",
							Required: true,
						},
						&cli.StringFlag{
							Name:     "signature",
							Required: true,
						},
					},
				},
			},
		},
	}
	app.Run(os.Args)
}

func serviceNameVithVersion() string {
	return ServiceName + "-" + Version
}

func setLog(c *cli.Context) {
	log = logger.NewLoggerService().SetServiceName(serviceNameVithVersion())
	switch strings.ToUpper(c.String("log-level")) {
	case "DEBUG":
		log.SetLevel(logger.DebugLevel)
		log.Debug("DEBUG log level has been set")
	case "INFO":
		log.SetLevel(logger.InfoLevel)
		log.Info("INFO log level has been set")
	case "WARNING":
		log.SetLevel(logger.WarningLevel)
	case "ERROR":
		log.SetLevel(logger.ErrorLevel)
	case "FATAL":
		log.SetLevel(logger.FatalLevel)
	default:
		log.SetLevel(logger.ErrorLevel)
		log.Errorf("Unknown flag value: log-level=%s. log-level should be from list: DEBUG/INFO/WARNING/ERROR/FATAL."+
			" Starting with ERROR log level", c.String("log-level"))
	}
}

func getKyberAlg(c *cli.Context) *kyber.Kyber {
	switch strings.ToLower(c.String("alg")) {
	case "kyber512":
		return kyber.NewKyber512()
	case "kyber768":
		return kyber.NewKyber768()
	case "kyber1024":
		return kyber.NewKyber1024()
	}
	log.Fatalf("Unknown flag value: alg=%s. alg should be from list: kyber512/kyber768/kyber1024", fatalExitCode, c.String("alg"))
	return nil
}

func getDilithiumAlg(c *cli.Context) *dilithium.Dilithium {
	switch strings.ToLower(c.String("alg")) {
	case "dilithium2":
		return dilithium.NewDilithium2()
	case "dilithium3":
		return dilithium.NewDilithium3()
	case "dilithium5":
		return dilithium.NewDilithium5()
	}
	log.Fatalf("Unknown flag value: alg=%s. alg should be from list: dilithium2/dilithium3/dilithium5", fatalExitCode, c.String("alg"))
	return nil
}

func getSeed(c *cli.Context) []byte {
	if str := c.String("seed"); str != "" {
		seed, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			log.Fatalf("Cannot decode base64 string: seed=%s. error: %v", fatalExitCode, str, err)
		}
		if len(seed) < 32 {
			log.Fatalf("Cannot decode base64 string: seed=%s. error: seed must be 32 bytes encoded to base64 string", fatalExitCode, str)
		}
		log.Info("Seed has been set")
		return seed
	}
	return nil
}
